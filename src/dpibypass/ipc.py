"""Arka plan servisi ile GUI arasındaki yerel soket protokolü.

Satır başına bir JSON nesnesi. İstek ``{"cmd": ..., ...}``, yanıt
``{"ok": bool, "data"|"error": ...}``.
"""

from __future__ import annotations

import asyncio
import grp
import json
import logging
import os
import socket
import stat as stat_module
from typing import Any, Awaitable, Callable

from .constants import (IPC_MAX_MESSAGE_BYTES, SOCKET_GROUP, SOCKET_MODE,
                        SOCKET_MODE_DEGRADED, SOCKET_PATH)

log = logging.getLogger("dpibypass.ipc")

Handler = Callable[[dict], Awaitable[dict]]


def _protocol_error(code: str, message: str) -> dict:
    """Protokol katmanındaki deterministik hata yanıtını üret."""
    return {"ok": False, "error": message, "code": code}


#: Bir sayının, ``true``/``false``/``null`` gibi bir sabitin JSON gösterimi için
#: fazlasıyla yeten üst sınır. Ölçüm tarafında fazla saymamak önemli: fazla
#: sayarsak sığan bir yanıtı yanlışlıkla reddederiz.
_SCALAR_BUDGET = 32


def _iter_mapping(mapping: dict):
    """Sözlüğü anahtar/değer akışı olarak, tembel biçimde gez."""
    for key, item in mapping.items():
        yield key
        yield item


def _within_budget(value: Any, limit: int) -> bool:
    """Yanıtın bütçeye sığma ihtimalini hiçbir şey tahsis etmeden ölç.

    Bu ön eleme olmadan boyut denetimi geç kalıyor. ``iterencode`` yalnızca
    *yapıyı* tembel gezer, tek bir dizeyi değil: 20 MB'lık bir dize tek parça
    olarak gelir, yani hem json'un kaçışlanmış kopyası hem de bizim
    ``encode("utf-8")`` çıktımız, çerçeve limiti kontrol edilmeden önce ayrılır.
    Sınırı ancak hiç kodlama yapmadan uygulayabiliriz.

    Gezinti tembeldir ve bütçe tükenir tükenmez durur, bu yüzden devasa bir
    yanıtın yalnızca ilk birkaç elemanına dokunulur. Ölçü karakter cinsindendir
    ve ayraçlar/virgüller sayılmaz; yani gerçek bayt boyutunu *eksik* tahmin
    eder. Yön bilinçli: eksik tahmin en fazla kesin denetime bir tur fazladan
    iş bırakır, fazla tahmin ise geçerli bir yanıtı reddederdi. Buradan geçen
    bir yanıt ``limit`` karakterden kısadır, dolayısıyla kodlanmış hâli de en
    fazla dört katı bayt tutar - sabit bir üst sınır.
    """
    remaining = limit
    pending = [iter((value,))]
    while pending:
        try:
            current = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue

        if isinstance(current, str):
            remaining -= len(current) + 2  # tırnaklar
        elif isinstance(current, dict):
            remaining -= 2
            pending.append(_iter_mapping(current))
        elif isinstance(current, (list, tuple)):
            remaining -= 2
            pending.append(iter(current))
        else:
            # Sayılar, bool'lar, None ve json'un kodlayamayacağı her şey. Kodlanamayan
            # bir tür için karar bizim değil: TypeError'ı encoder üretsin, biz onu
            # "çok büyük" diye raporlamayalım.
            remaining -= _SCALAR_BUDGET

        if remaining < 0:
            return False
    return True


def _encode_bounded(value: Any, limit: int) -> bytes | None:
    """JSON'u sınırlı bellekle kodla; bütçe aşılırsa ``None`` dön.

    ``json.dumps`` tüm çıktıyı önce bellekte kurar, bu yüzden boyut sınırı ancak
    devasa bir dize zaten ayrıldıktan sonra devreye girerdi: 256 KiB'lik çerçeve
    limiti, yüz megabaytlık bir yanıtın tahsisini engellemez, yalnızca tahsis
    bittikten sonra yazılmasını engeller.

    Sınırı gerçekten uygulamak iki aşama gerektiriyor. Önce hiçbir şey tahsis
    etmeyen ölçüm, ki tek bir devasa dizeyi de kapsayan tek yol odur; sonra,
    yalnızca ölçümü geçen yanıtlar için, kesin bayt denetimi. İkinci aşamaya
    ulaşan her şeyin ``limit`` karakterden kısa olduğu bilinir, bu yüzden tepe
    bellek kullanımı yanıtın gerçek boyutundan bağımsız olarak sınırlıdır.
    """
    if not _within_budget(value, limit):
        return None

    chunks: list[bytes] = []
    total = 0
    for chunk in json.JSONEncoder(ensure_ascii=False).iterencode(value):
        encoded = chunk.encode("utf-8")
        total += len(encoded)
        if total > limit:
            return None
        chunks.append(encoded)
    return b"".join(chunks)


class IpcServer:
    def __init__(self, handler: Handler, path: str = SOCKET_PATH,
                 group: str = SOCKET_GROUP) -> None:
        self.handler = handler
        self.path = path
        self.group = group
        #: Soket beklenen grup/kip ile kurulabildi mi? Kurulamadıysa soket
        #: yalnızca root'a açıktır ve GUI/CLI bunu bir servis sorunu olarak
        #: bildirir — sessizce herkese açılmaz.
        self.degraded = False
        self.degraded_reason = ""
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        # Varsayılan soket yolu /run/dpi-bypass altında kalır; ancak testler
        # ve gömülü kullanımlar özel bir yol verdiğinde onun üst dizinini
        # hazırlamalıyız. Global RUN_DIR kullanmak path parametresini fiilen
        # görmezden geliyor ve root olmayan ortamlarda gereksiz /run yazma
        # denemesine yol açıyordu.
        socket_dir = os.path.dirname(self.path)
        if socket_dir:
            os.makedirs(socket_dir, mode=0o755, exist_ok=True)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        # Soket, izinleri ayarlanana kadar bile geniş açılmasın: asyncio
        # soketi umask'e göre oluşturur, bu yüzden önce dar bir umask kur.
        previous_umask = os.umask(0o177)
        try:
            # StreamReader'ın varsayılan yaklaşık 64 KiB sınırına dolaylı
            # olarak güvenmek yerine protokolün açık ve iki yönlü limitini
            # kullan. Aşım _client içinde kontrollü hata yanıtına çevrilir.
            self._server = await asyncio.start_unix_server(
                self._client, path=self.path, limit=IPC_MAX_MESSAGE_BYTES)
        finally:
            os.umask(previous_umask)
        self._set_permissions()
        log.info("Denetim soketi: %s", self.path)

    def _set_permissions(self) -> None:
        """Soketi ``root:dpi-bypass`` / ``0660`` yap ve sonucu **doğrula**.

        Bu soket root servisini yöneten bir denetim kanalıdır; grup
        çözülemezse ya da izinler istendiği gibi uygulanamazsa soket herkese
        açılmaz — yalnızca root'a bırakılır (``0600``) ve durum ``degraded``
        olarak işaretlenir.
        """
        self.degraded = False
        self.degraded_reason = ""
        try:
            gid = int(grp.getgrnam(self.group).gr_gid)
        except (KeyError, TypeError, ValueError):
            self._degrade(f"'{self.group}' grubu sistemde tanımlı değil")
            return
        try:
            os.chown(self.path, 0, gid)
            os.chmod(self.path, SOCKET_MODE)
        except OSError as exc:
            self._degrade(f"soket izinleri ayarlanamadı: {exc}")
            return
        # Uygulandığını varsayma; gerçekten okunup doğrulanır.
        try:
            info = os.stat(self.path)
        except OSError as exc:
            self._degrade(f"soket durumu okunamadı: {exc}")
            return
        mode = stat_module.S_IMODE(info.st_mode)
        if info.st_gid != gid or info.st_uid != 0 or mode != SOCKET_MODE:
            self._degrade(
                f"soket beklenen sahiplikte değil (uid={info.st_uid}, "
                f"gid={info.st_gid}, kip=0{mode:o})")
            return
        log.info("Soket izinleri: root:%s 0%o", self.group, SOCKET_MODE)

    def _degrade(self, reason: str) -> None:
        """Güvenli tarafa düş: soketi yalnız root'a bırak ve gürültülü logla."""
        self.degraded = True
        self.degraded_reason = reason
        try:
            os.chmod(self.path, SOCKET_MODE_DEGRADED)
        except OSError as exc:
            reason = f"{reason}; ayrıca 0{SOCKET_MODE_DEGRADED:o} da uygulanamadı: {exc}"
            self.degraded_reason = reason
        log.error(
            "Denetim soketi güvenli kipe düşürüldü (0%o, yalnız root): %s. "
            "GUI ve komut satırı bağlanamayacak; kurulumu onarın "
            "(sudo groupadd --system %s && sudo systemctl restart dpi-bypass).",
            SOCKET_MODE_DEGRADED, reason, self.group)

    def status(self) -> dict:
        """Soketin gerçek durumu — tanı ekranları için."""
        data: dict[str, Any] = {
            "path": self.path,
            "group": self.group,
            "degraded": self.degraded,
            "reason": self.degraded_reason,
            "expected_mode": f"0{SOCKET_MODE:o}",
        }
        try:
            info = os.stat(self.path)
        except OSError:
            data.update({"exists": False, "uid": None, "gid": None, "mode": None})
            return data
        data.update({
            "exists": True,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": f"0{stat_module.S_IMODE(info.st_mode):o}",
        })
        return data

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        try:
            os.unlink(self.path)
        except OSError:
            pass

    async def _send_response(self, writer: asyncio.StreamWriter,
                             response: Any) -> None:
        """Yanıtı doğrula, boyutlandır ve tek bir sınırlı JSON satırı yaz."""
        if not isinstance(response, dict):
            log.error("IPC işleyici nesne olmayan yanıt döndürdü: %s",
                      type(response).__name__)
            response = _protocol_error(
                "invalid-response", "servis geçersiz yanıt üretti")
        # Satır sonu da çerçevenin parçası, bütçeden bir bayt ayır.
        budget = IPC_MAX_MESSAGE_BYTES - 1
        try:
            body = _encode_bounded(response, budget)
        except (TypeError, ValueError) as exc:
            log.exception("IPC yanıtı JSON olarak kodlanamadı")
            body = _encode_bounded(
                _protocol_error(
                    "invalid-response", f"servis yanıtı kodlanamadı: {exc}"),
                budget)
        if body is None:
            log.error("IPC yanıtı boyut sınırını aştı: > %d bayt", budget)
            body = _encode_bounded(
                _protocol_error(
                    "response-too-large", "servis yanıtı boyut sınırını aştı"),
                budget)
        # Protokol hatalarının kendisi de bütçeye sığmıyorsa (çok küçük bir
        # IPC_MAX_MESSAGE_BYTES) sabit bir çerçeve yaz: yazmamak istemciyi
        # zaman aşımına bırakırdı.
        if body is None:
            body = b'{"ok":false,"code":"response-too-large"}'
        writer.write(body + b"\n")
        await writer.drain()

    async def _client(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                try:
                    line = await reader.readline()
                except ValueError:
                    # StreamReader, ayarlanan limit aşılınca ValueError üretir.
                    # İstemciye anlaşılır bir protokol hatası verip bağlantıyı
                    # kapat; aynı akışta çerçeve sınırını yeniden eşlemek güvenli
                    # değildir.
                    await self._send_response(
                        writer,
                        _protocol_error(
                            "request-too-large", "istek boyut sınırını aştı"),
                    )
                    break
                if not line:
                    break
                # EOF ile sonlanan bir çerçevede StreamReader doğrudan baytları
                # döndürebilir; limit kontrolünü bu yol için de açıkça uygula.
                if len(line) > IPC_MAX_MESSAGE_BYTES:
                    await self._send_response(
                        writer,
                        _protocol_error(
                            "request-too-large", "istek boyut sınırını aştı"),
                    )
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                    if not isinstance(request, dict):
                        raise ValueError("nesne bekleniyordu")
                except (ValueError, UnicodeDecodeError) as exc:
                    response = {"ok": False, "error": f"geçersiz istek: {exc}"}
                else:
                    try:
                        response = await self.handler(request)
                    except Exception as exc:  # işleyici hatası bağlantıyı düşürmesin
                        log.exception("IPC işleyici hatası")
                        response = {"ok": False, "error": str(exc)}
                await self._send_response(writer, response)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class IpcClient:
    """Eşzamanlı istemci (GUI ve komut satırı için)."""

    def __init__(self, path: str = SOCKET_PATH, timeout: float = 30.0) -> None:
        self.path = path
        self.timeout = timeout

    def call(self, cmd: str, **kwargs: Any) -> dict:
        request = {"cmd": cmd}
        request.update(kwargs)
        # JSON kodlama ve çerçeve limiti soket açılmadan önce doğrulanır. Böylece
        # yerel programlama hatası servis erişim hatası gibi raporlanmaz.
        try:
            body = _encode_bounded(request, IPC_MAX_MESSAGE_BYTES - 1)
        except (TypeError, ValueError) as exc:
            return _protocol_error(
                "invalid-request", f"istek JSON olarak kodlanamadı: {exc}")
        if body is None:
            return _protocol_error(
                "request-too-large", "istek boyut sınırını aştı")
        payload = body + b"\n"

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
            sock.sendall(payload)
            buf = bytearray()
            while b"\n" not in buf:
                # Bir adet fazladan bayt okumaya izin ver; bu sayede sınırın
                # aşıldığını kesin biçimde saptarken bellek büyümesi sınırlı
                # kalır. Normal yanıtlar ilk yeni satırda hemen sonlanır.
                remaining = IPC_MAX_MESSAGE_BYTES + 1 - len(buf)
                if remaining <= 0:
                    return _protocol_error(
                        "response-too-large", "servis yanıtı boyut sınırını aştı")
                chunk = sock.recv(min(65536, remaining))
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > IPC_MAX_MESSAGE_BYTES:
                    return _protocol_error(
                        "response-too-large", "servis yanıtı boyut sınırını aştı")
            if not buf:
                return {"ok": False, "error": "servisten yanıt yok"}
            try:
                response = json.loads(
                    bytes(buf).split(b"\n", 1)[0].decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                return _protocol_error("invalid-response", f"bozuk yanıt: {exc}")
            if not isinstance(response, dict):
                return _protocol_error(
                    "invalid-response", "servis yanıtı JSON nesnesi değil")
            return response
        except FileNotFoundError:
            return {"ok": False, "error": "servis çalışmıyor (soket yok)",
                    "code": "no-service"}
        except PermissionError:
            # Sebebi burada tahmin etme: grup üyeliği, oturum grup listesi ve
            # soket izinleri farklı sorunlardır. Tanıyı session_access yapar.
            return {"ok": False,
                    "error": "denetim soketine erişim reddedildi",
                    "code": "permission"}
        except (ConnectionRefusedError, OSError) as exc:
            return {"ok": False, "error": f"servise bağlanılamadı: {exc}",
                    "code": "no-service"}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def available(self) -> bool:
        return os.path.exists(self.path)
