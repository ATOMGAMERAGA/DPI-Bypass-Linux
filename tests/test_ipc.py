"""Yerel daemon IPC protokolü için sınır ve biçim regresyon testleri."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from dpibypass import ipc  # noqa: E402


class TestIpcServerProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tempdir.name, "daemon.sock")
        self.server = None

    async def asyncTearDown(self) -> None:
        if self.server is not None:
            await self.server.stop()
        self.tempdir.cleanup()

    async def _start(self, handler):
        self.server = ipc.IpcServer(handler, path=self.path, group="unused")
        # Bu testler root/grup izinlerini değil protokolü sınar; soket sahipliği
        # için gerçek chown çağırmadan yerel Unix soketiyle uçtan uca çalışır.
        self.server._set_permissions = mock.Mock()
        await self.server.start()
        return self.server

    async def _exchange(self, payload: bytes) -> dict:
        reader, writer = await asyncio.open_unix_connection(self.path)
        try:
            writer.write(payload)
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), 2)
            self.assertTrue(line, "sunucu yanıt vermeden bağlantıyı kapattı")
            return json.loads(line.decode("utf-8"))
        finally:
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()

    async def test_valid_request_round_trip(self):
        async def handler(request):
            return {"ok": True, "data": request["value"]}

        await self._start(handler)
        response = await self._exchange(b'{"cmd":"echo","value":42}\n')
        self.assertEqual(response, {"ok": True, "data": 42})

    async def test_oversized_request_is_rejected_before_handler(self):
        handler = mock.AsyncMock(return_value={"ok": True})
        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 128):
            await self._start(handler)
            response = await self._exchange(b"{" + b"x" * 512 + b"}\n")

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "request-too-large")
        handler.assert_not_awaited()

    async def test_non_mapping_handler_response_is_normalized(self):
        async def handler(_request):
            return ["not", "a", "mapping"]

        await self._start(handler)
        response = await self._exchange(b'{"cmd":"status"}\n')
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "invalid-response")

    async def test_oversized_handler_response_is_not_written(self):
        async def handler(_request):
            return {"ok": True, "data": "x" * 1024}

        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 256):
            await self._start(handler)
            response = await self._exchange(b'{"cmd":"status"}\n')

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "response-too-large")

    async def test_oversized_response_is_refused_without_full_serialization(self):
        payload = _LazyHugeList(100_000)

        async def handler(_request):
            return {"ok": True, "data": payload}

        await self._start(handler)
        response = await self._exchange(b'{"cmd":"status"}\n')

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "response-too-large")
        self.assertLess(
            payload.consumed, 1024,
            "sunucu sınırı aşan yanıtı yine de tümüyle serileştirdi")


class _LazyHugeList(list):
    """Serileştirilirse devasa olan, ama tembel üretilen bir dizi.

    Tüm veriyi gerçekten ayırmadan "işleyici çok büyük bir yanıt döndürdü"
    durumunu kurar, böylece test kodlayıcının nereye kadar ilerlediğini
    ölçebilir.
    """

    def __init__(self, items: int) -> None:
        super().__init__()
        self.items = items
        self.consumed = 0

    def __len__(self) -> int:
        return self.items

    def __iter__(self):
        for _ in range(self.items):
            self.consumed += 1
            yield "x" * 1024


class TestBoundedEncoding(unittest.TestCase):
    def test_encoder_stops_at_the_budget_instead_of_building_the_whole_frame(self):
        # 100 MB'lık bir yanıt: json.dumps ile önce tamamı bellekte kurulurdu ve
        # 256 KiB'lik çerçeve limiti ancak ondan sonra devreye girerdi.
        payload = _LazyHugeList(100_000)

        self.assertIsNone(
            ipc._encode_bounded({"ok": True, "data": payload}, 4096))
        self.assertLess(
            payload.consumed, 64,
            "kodlayıcı bütçe aşıldıktan sonra da veriyi tüketmeyi sürdürdü")

    def test_a_single_huge_string_is_refused_before_anything_encodes_it(self):
        """iterencode yapıyı tembel gezer, tek bir dizeyi değil.

        Devasa bir dize tek parça olarak gelir; onu görebilmek için json'un
        kaçışlanmış kopyasının zaten ayrılmış olması gerekir. Sınır ancak hiç
        kodlama yapılmadan uygulanabilir, bu yüzden test kodlayıcının hiç
        kurulmadığını doğrular.
        """
        payload = {"ok": True, "data": "x" * 1_000_000}

        with mock.patch.object(
            ipc.json, "JSONEncoder",
            side_effect=AssertionError("kodlayıcı bütçe denetiminden önce çalıştı"),
        ):
            self.assertIsNone(ipc._encode_bounded(payload, 4096))

    def test_measurement_touches_only_what_it_needs_to_decide(self):
        # Ölçüm de tembel olmalı: bütçe tükendikten sonra gezinmeyi sürdürmek,
        # kaçınmaya çalıştığımız işin ta kendisini yapmak olurdu.
        payload = _LazyHugeList(100_000)

        self.assertFalse(ipc._within_budget({"ok": True, "data": payload}, 4096))
        self.assertLess(payload.consumed, 64)

    def test_measurement_does_not_reject_a_frame_that_fits(self):
        # Ölçüm eksik tahmin etmeli: fazla saymak geçerli bir yanıtı reddederdi.
        frame = {"ok": True, "data": {"ports": [1, 2, 3], "note": "ölçüm", "on": True}}

        self.assertTrue(ipc._within_budget(frame, 256))
        self.assertIsNotNone(ipc._encode_bounded(frame, 256))

    def test_unencodable_values_stay_the_encoder_s_error_to_raise(self):
        # "Kodlanamaz" ile "çok büyük" farklı hatalar; ön eleme bunu karıştırmamalı.
        with self.assertRaises(TypeError):
            ipc._encode_bounded({"ok": True, "data": object()}, 4096)

    def test_encoder_returns_the_exact_frame_when_it_fits(self):
        encoded = ipc._encode_bounded({"ok": True, "data": "ölçüm"}, 4096)

        self.assertIsNotNone(encoded)
        self.assertEqual(json.loads(encoded.decode("utf-8")),
                         {"ok": True, "data": "ölçüm"})
        # ensure_ascii=False korunmalı: aksi halde Türkçe metin kaçışlanır ve
        # çerçeve boyutu sessizce büyür.
        self.assertIn("ölçüm".encode("utf-8"), encoded)


class TestIpcClientProtocol(unittest.TestCase):
    def test_non_serializable_request_fails_before_socket_creation(self):
        with mock.patch.object(ipc.socket, "socket") as socket_ctor:
            response = ipc.IpcClient("/unused").call("test", value=object())

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "invalid-request")
        socket_ctor.assert_not_called()

    def test_oversized_request_fails_before_socket_creation(self):
        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 64), \
                mock.patch.object(ipc.socket, "socket") as socket_ctor:
            response = ipc.IpcClient("/unused").call("test", value="x" * 128)

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "request-too-large")
        socket_ctor.assert_not_called()

    def test_response_without_newline_is_bounded(self):
        fake_socket = mock.Mock()
        fake_socket.recv.side_effect = [b"x" * 64, b"x"]
        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 64), \
                mock.patch.object(ipc.socket, "socket", return_value=fake_socket):
            response = ipc.IpcClient("/unused").call("status")

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "response-too-large")
        fake_socket.close.assert_called_once()

    def test_non_mapping_response_is_rejected(self):
        fake_socket = mock.Mock()
        fake_socket.recv.return_value = b"[]\n"
        with mock.patch.object(ipc.socket, "socket", return_value=fake_socket):
            response = ipc.IpcClient("/unused").call("status")

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "invalid-response")


if __name__ == "__main__":
    unittest.main(verbosity=2)
