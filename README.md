<div align="center">

<img src="data/icons/hicolor/256x256/apps/xyz.atomland.DpiBypass.png" width="128" alt="DPI Bypass">

# DPI Bypass

**Türkiye'deki DPI tabanlı engelleri aşan, ağ değiştiğinde yöntemi kendiliğinden
yeniden bulan GNOME uygulaması.**

Discord başta olmak üzere derin paket incelemesi (DPI) ile engellenen sitelere
erişimi açar. VPN değildir: trafik başka bir ülkeye çıkmaz, ping ve gecikme
etkilenmez.

*Yazan: Atom Gamer Arda A.G.A*

</div>

---

## Tek satırlık kurulum

```bash
curl -fsSL https://raw.githubusercontent.com/atomgameraga/DPI-Bypass-Linux/main/install.sh | sudo bash
```

Betik işletim sistemini kendi saptar, gereken paketleri kurar, servisi
etkinleştirir ve bitince **"Buradan sonrasına GUI uygulamasından devam edin"**
der. Uygulamayı Etkinlikler menüsünde **DPI Bypass** adıyla bulursunuz.

Desteklenen dağıtımlar: **Fedora / RHEL / Rocky / Alma, Ubuntu / Debian / Mint /
Pop!\_OS / Kali, Arch / Manjaro / EndeavourOS, openSUSE, Alpine, Void, Solus**
ve `dnf / apt / pacman / zypper / apk / xbps / eopkg` kullanan diğerleri.

Kaldırmak için:

```bash
sudo bash install.sh --uninstall
```

---

## Ne yapıyor?

| Katman | Yapılan iş |
|---|---|
| **DNS** | Sistemin tüm DNS trafiği (53/udp, 53/tcp) yerel köprüye yönlendirilir ve **DNS-over-HTTPS** ile taşınır. Birincil **Cloudflare**, yedekler **Google** ve **Quad9**. DNS zehirlenmesi ve DNS düzeyindeki engel böylece tamamen aşılır. |
| **DPI** | Engelli hedeflere giden TCP 80/443 bağlantıları yerel şeffaf vekile düşer. İlk istemci verisi (TLS ClientHello / HTTP isteği) seçilen stratejiye göre yeniden şekillendirilerek gönderilir; sunucu veriyi eksiksiz alır, yol üstündeki DPI ise SNI'yi göremez. |
| **QUIC** | İsteğe bağlı olarak engelli hedeflere UDP/443 reddedilir; tarayıcılar atlatma uygulanabilen TCP'ye döner. |
| **Diğer trafik** | Yönlendirilmez. ICMP (ping), oyun/VoIP UDP trafiği, torrent, VPN — hiçbiri vekilden geçmez, ölçülebilir bir etki oluşmaz. |

### Atlatma yöntemleri

Hepsi kullanıcı alanında çalışır; çekirdek modülü ya da NFQUEUE gerekmez.

| Yöntem | Nasıl çalışır |
|---|---|
| `tlsrec` | ClientHello birden çok **TLS kaydına** bölünür. TLS açısından tamamen geçerlidir; kayıt katmanını birleştirmeyen DPI SNI'yi bulamaz. Ek gecikme yoktur. |
| `split` | İlk veri, SNI'nin ortasından ayrı TCP segmentlerine bölünür. |
| `disorder` | Baştaki parça **düşük TTL** ile gönderilir: DPI görür, sunucuya ulaşmaz. İkinci parça normal gider; çekirdek kayıp parçayı normal TTL ile yeniden iletir. DPI akışı eksik görür, sunucu eksiksiz alır. |
| `oob` | Parçaların arasına `MSG_OOB` ile "acil" bayt konur. Akışı satır içi birleştiren DPI bu baytı veriye katıp SNI'yi bozar; sunucunun TCP yığını acil baytı akıştan düşürür. |
| `disoob` | `disorder` + `oob`. |
| `fake` | Gerçek veriden önce, zararsız bir SNI taşıyan sahte bir ClientHello **ham soketle ve gerçek verinin sıra numarasıyla** düşük TTL kullanılarak gönderilir. Çekirdeğin gönderim kuyruğuna hiç girmediği için gerçek veri bozulmaz. |

Toplam 16 hazır varyant vardır (`dpi-bypass strategies`).

### Yöntem nasıl seçiliyor?

1. **Operatör saptanır.** Genel IP adresinden Team Cymru'nun DNS tabanlı IP→ASN
   servisiyle (DoH üzerinden) ASN ve AS adı okunur; buna bağlantı türü
   (wifi / ethernet / mobil) ve SSID eklenir. Ekrandaki listenin tamamı desteklenir:

   > Türk Telekom (Mobil) · Türk Telekom Evde İnternet · Türk Telekom Hotspot ·
   > Redbox (Türk Telekom) · Turkcell (Mobil) · Turkcell Superonline ·
   > Superbox (Turkcell FWA) · Turkcell Hotspot · Vodafone (Mobil) ·
   > Vodafone Evde İnternet · Vodafone Hotspot · TurkNet · Diğer / Bilinmiyor

2. **O operatörün sırası denenir.** Her yöntem `discord.com` üzerinde *gerçek*
   bir TLS el sıkışması + HTTP isteğiyle sınanır. "Bağlantı kuruldu" demek
   yetmez: DPI çoğu zaman TCP el sıkışmasına izin verip ClientHello'dan sonra
   RST gönderir; bu yüzden sunucudan gerçek yanıt beklenir.

3. **Çalışan yöntem ikinci bir uç noktayla doğrulanır** (`gateway.discord.gg`)
   ve o ağın parmak izine kaydedilir.

### Ağ değişince ne oluyor?

Çekirdekten gelen **netlink** olayları anında yakalanır. Ağ parmak izi
(arayüz + ağ geçidi + ağ geçidi MAC + SSID + bağlantı türü) değiştiğinde —
örneğin `atom` ağından `atoms hotspot` ağına geçtiğinizde — arama arka planda
yeniden başlar. O ağ daha önce görüldüyse kayıtlı yöntem **ilk sırada** denenir,
böylece geçiş çoğunlukla tek denemede ve saniyeler içinde tamamlanır.

Seçili yöntem sonradan çalışmayı bırakırsa (operatör kural değiştirirse)
başarısız bağlantılar sayılır ve arama kendiliğinden tekrarlanır.

### Her sitede çalışması

- Yerleşik listede Discord'un tüm alan adları ve Türkiye'de DPI ile engellendiği
  bilinen diğer adresler vardır.
- **Otomatik keşif:** açtığınız yeni bir alan adı, atlatmasız açılmayıp
  atlatmayla açılıyorsa sessizce sınanıp kalıcı olarak listeye eklenir.
- Dilediğiniz alan adını arayüzden elle de ekleyebilirsiniz (alt alan adları
  kapsanır).
- "Tüm siteler" kipinde 80/443'ün tamamı vekilden geçer.

---

## Arayüz

GTK4 + libadwaita ile yazılmıştır; GNOME'un kendi bileşenlerini kullanır
(`Adw.ViewStack`, `Adw.PreferencesPage`, `Adw.SwitchRow`, `Adw.ComboRow`,
`Adw.ToastOverlay`, `Adw.AboutDialog`…). Koyu/açık tema, dar ekran uyumu ve
libadwaita 1.2+ sürümleriyle geriye dönük uyumluluk vardır.

Sayfalar: **Durum** (tek dokunuşla aç/kapat, canlı bilgi, "yeniden ara" ve
"discord.com'u test et"), **Ayarlar**, **Siteler**, **Günlük**.

---

## Komut satırı

```bash
dpi-bypass status          # genel durum
dpi-bypass search --wait   # yöntemi yeniden ara
dpi-bypass test            # discord.com erişimini sına
dpi-bypass test oob-snimid # belirli bir yöntemi sına
dpi-bypass detect          # operatörü yeniden sapta
dpi-bypass strategies      # yöntem listesi
dpi-bypass logs -f         # canlı günlük
dpi-bypass set mode=all dns_provider=quad9
dpi-bypass disable / enable
```

---

## Servis

Kurulum `dpi-bypass.service` birimini kaydeder ve etkinleştirir; **sistem
açılışında kendiliğinden başlar**.

```bash
systemctl status dpi-bypass
journalctl -u dpi-bypass -f
```

Servis durduğunda tüm çekirdek kuralları geri alınır (`ExecStopPost`), sistem
hiçbir zaman yarım kurulmuş kurallarla kalmaz.

`dpi-bypass` grubundaki kullanıcılar arayüzden servisi parola sormadan
yönetebilir (polkit kuralı kurulur). Kurulum betiği sizi bu gruba ekler.

---

## Ayarlar

`/etc/dpi-bypass/config.json`

| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `enabled` | `true` | Koruma açık mı |
| `mode` | `smart` | `smart` = yalnız engelli liste, `all` = tüm 80/443 |
| `isp` | `auto` | Operatör profili (`auto` ya da profil kimliği) |
| `strategy` | `auto` | Atlatma yöntemi (`auto` ya da yöntem adı) |
| `dns_provider` | `cloudflare` | `cloudflare` / `google` / `quad9` |
| `dns_intercept` | `true` | 53 numaralı portu yakala |
| `block_quic` | `true` | Engelli hedeflere UDP/443'ü reddet |
| `auto_switch` | `true` | Ağ değişince yeniden ara |
| `auto_discover` | `true` | Yeni engelli siteleri kendiliğinden bul |
| `recheck_interval` | `1800` | Düzenli denetim aralığı (saniye, 0 = kapalı) |
| `extra_domains` | `[]` | Elle eklenen alan adları |
| `gui_autostart` | `true` | Oturum açılışında arayüzü başlat |

Öğrenilen ağlar ve alan adları: `/var/lib/dpi-bypass/state.json`

---

## Gereksinimler

- Linux, systemd
- Python 3.8+
- nftables (yoksa iptables)
- GTK 4 + libadwaita 1.2+ ve PyGObject (yalnızca arayüz için)
- Servis root olarak çalışır (`CAP_NET_ADMIN`, `CAP_NET_RAW`)

---

## Geliştirme

```bash
git clone https://github.com/atomgameraga/DPI-Bypass-Linux
cd DPI-Bypass-Linux
python3 -m unittest discover -s tests -v     # testler
sudo python3 bin/dpi-bypassd -v              # servisi kaynaktan çalıştır
python3 bin/dpi-bypass-gui                   # arayüzü kaynaktan çalıştır
sudo bash install.sh                         # yerel ağaçtan kur
```

Proje düzeni:

```
src/dpibypass/
  daemon.py      düzenleyici: saptama, arama, olay akışı
  desync.py      stratejilerin sokete uygulanması
  strategies.py  yöntem kataloğu
  rawfake.py     ham soketle sahte paket enjeksiyonu
  tlsutil.py     ClientHello ayrıştırma ve kayıt parçalama
  tlsclient.py   bellek BIO tabanlı TLS istemcisi (DoH ve testler için)
  resolver.py    DNS-over-HTTPS çözümleyici
  dnsserver.py   yerel DNS köprüsü
  proxy.py       şeffaf TCP vekil
  firewall.py    nftables / iptables kuralları
  netmon.py      netlink ağ değişikliği izleyicisi
  isps.py        operatör profilleri ve saptama
  tester.py      gerçek bağlantı testleri
  ipc.py         servis ↔ arayüz protokolü
  gui/           GTK4 + libadwaita arayüz
```

---

## Yasal uyarı

Bu araç, ağ üzerinde uygulanan sansürü aşmak için tasarlanmış açık kaynak bir
yazılımdır. Kullanım sorumluluğu tamamen kullanıcıya aittir; bulunduğunuz
ülkenin mevzuatına uymak sizin sorumluluğunuzdadır.

## Lisans

GPL-3.0-or-later — bkz. [LICENSE](LICENSE).
