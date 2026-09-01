<div align="center">

<img src="data/icons/hicolor/256x256/apps/xyz.atomland.DpiBypass.png" width="128" alt="DPI Bypass">

# DPI Bypass

**Türkiye'deki DPI tabanlı engelleri aşan, ağ değiştiğinde yöntemi kendiliğinden
yeniden bulan GNOME uygulaması.**

Discord başta olmak üzere derin paket incelemesi (DPI) ile engellenen sitelere
erişimi açar. VPN değildir: trafik başka bir ülkeye çıkmaz, ping ve gecikme
atlatma için başka bir sunucuya taşınmaz. İsteğe bağlı **Ping düşürme (Beta)**
kipi ise yalnız bilgisayardaki doğrulanabilir yerel gecikme nedenlerini ölçer.

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
| **Ping düşürme (Beta)** | Seçtiğiniz hedefe giden yolu doğrular, her adayı kontrol ölçümüyle iç içe (A/B/A) sınar ve kararı blok bootstrap güven aralığına dayandırır. Kazananı bağımsız bloklarla yeniden doğrular; yalnız o kalır, gerisi geri alınır. Kazanç yoksa hiçbir ayar değişmez. İsteğe bağlı SQM kipi, gerçek `bandwidth` ile yük altındaki gecikmeyi düşürür. |
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

## Ping düşürme (Beta)

Bu özellik bir VPN değildir; ISP rotasını, fiziksel mesafeyi veya uzak
sunucunun yükünü değiştiremez ve her ağda daha düşük ping garanti etmez. Esas
amacı bilgisayar kaynaklı yerel kuyruklanma ve jitter nedenlerini azaltmak,
özellikle **yük altında oluşan ping sıçramalarını** düşürmektir.

### Nasıl çalışır: zaman bakımından eşleştirilmiş A/B ölçümü

Tek bir ayarı uygulayıp "oldu" demek yeterli değildir; ağ ölçüm sırasında
kendiliğinden de iyileşebilir. Bu yüzden her aday **kontrol ölçümüyle iç içe**
sınanır:

```
hedefleri çöz, yolu doğrula
  → blok 1: A ölç · B uygula-ölç-geri al
  → blok 2: B uygula-ölç-geri al · A ölç      (sıra dengelenir: ABBA)
  → blok 3: …
  → blok çiftlerinin farkları üzerinden blok bootstrap güven aralığı
  → kazananı BAĞIMSIZ holdout bloklarıyla yeniden doğrula
  → doğrulandıysa uygula, doğrulanmadıysa geri al
```

Kararın dayandığı üç kural:

1. **Havuzlama yok.** Her hedefin örnekleri kendi içinde özetlenir. Toplu
   gösterge hedef başına *eşit ağırlıklıdır*, yani bir hedefin çok, diğerinin
   az yanıt vermesi sahte kazanç üretemez. Yavaş bir hedefin susması iyileşme
   değil, kapsam kaybıdır ve reddedilir.
2. **Eşleştirme.** Fark, her B ölçümünün komşu A ölçümleriyle karşılaştırılması
   ile bulunur; ağın yavaş sürüklenmesi (drift) böylece adaya yazılamaz.
3. **Gürültü tabanı.** Kontrol kolu kendi içinde de karşılaştırılır (A/A).
   Hiçbir şey değiştirmeden görülen fark, hem "kazanç" hem "kötüleşme"
   kararının alt sınırıdır. Bu sayede sabit bir 2 ms duvarı olmadan, gerçek
   ve tekrarlanan **1 ms altı** kazançlar da değerlendirilebilir; buna karşılık
   saf gürültü hiçbir zaman kazanan seçtirmez.

Ağ ölçüm boyunca kararsızsa sonuç `no-gain` değil **`inconclusive`** olur.

### Ölçüm hedefi ve koşullar

Ölçüm hedefini siz seçersiniz. Hedef tanımlı değilse genel ağ göstergesi
adresleri kullanılır ve sonuç **açıkça öyle etiketlenir** — bu bir oyun ping'i
değildir.

```bash
dpi-bypass latency target add oyun.sunucum.net:7777 udp "Oyun sunucusu"
dpi-bypass latency target add 203.0.113.10 icmp
dpi-bypass latency target list
dpi-bypass latency target remove 0
```

Her hedef için IP, adres ailesi, protokol, port, arayüz, ifindex ve kaynak
adresi sabitlenir; biri değişirse ölçümler karşılaştırılamaz sayılır ve yeni
taban alınır. **DNS çözümleme süresi RTT'ye dahil edilmez**, ayrı raporlanır.
ICMP RTT, TCP connect, UDP yankı ve TLS el sıkışması ayrı metriklerdir ve
birbirinin yerine geçmez; bir TCP bağlantı hatasına "paket kaybı" denmez.

Hedefe giden gerçek rota `ip route get` ile doğrulanır. Trafik başka bir
arayüzden (örneğin VPN'den) gidiyorsa hedef ölçüme alınmaz — trafiği tünelin
dışına zorlamayız. `SO_MARK` konamazsa TCP/TLS örneği toplanmaz: işaretsiz bir
soket kendi şeffaf vekilimize düşebilir ve o zaman ölçülen şey ağ RTT'si
değildir.

Ölçüm koşulları birbirine karıştırılmaz:

| Koşul | Ne ölçer |
|---|---|
| `idle` | ısınmış, düşük trafikli RTT (varsayılan) |
| `first-packet` | kontrollü sessizlik sonrası **ilk** paketler — Wi-Fi güç tasarrufu hipotezi için |
| `natural-traffic` | kullanıcının kendi trafiği altında (gözlemsel) |
| `load-up` / `load-down` / `load-both` | yalnız izinli kontrollü yük testinde |

```bash
dpi-bypass latency test --condition first-packet
```

### Adaylar

| Aday | Ne zaman | Ne yapar |
|---|---|---|
| Wi-Fi güç tasarrufu | kablosuz arayüzde `iw` varsa ve güç tasarrufu açıksa | `iw dev … set power_save off`; uygulanan değer **geri okunarak** doğrulanır |
| `fq_codel` / `fq` / `cake` | kuyruk yapısının geri alma tarifi **kanıtlandıysa** | kök qdisc'i ya da `mq` yapraklarını değiştirir |
| EEE kapalı | Ethernet'te `ethtool --show-eee` "enabled" diyorsa | `ethtool --set-eee … eee off`, readback ile doğrulanır |
| RX coalescing | `ethtool -c` okunabiliyor **ve** değerler geri yazılabiliyorsa | tek bir agresif `0` yerine sürücünün desteklediği birkaç nokta denenir; kazananı ölçüm seçer |
| SQM (opt-in) | `latency_sqm` açık ve hat kapasitesi girilmişse | gerçek `bandwidth` ile CAKE (ya da HTB+`fq_codel`), mümkünse IFB ingress |

Kuyruk yapısı artık `tc -j -d` ile **yapılandırılmış** okunur (desteklenmiyorsa
dar bir metin yoluna düşülür). `mq` kökü silinmez; korunur ve yalnız tanınan
yaprakları aday olur — çok kuyruklu NIC'lerde eskiden hiçbir aday
denenemiyordu. Bir yapının aday olabilmesi için geri alma tarifi
`tc qdisc change` ile **uygulanarak kanıtlanır** (mevcut değerlerin aynısı
yazıldığı için no-op'tur) ve durum geri okunarak karşılaştırılır. Kanıtlanamayan,
allowlist dışı bir seçeneği olan ya da bağlı filter/class taşıyan yapı korunur.
Kullanıcının CAKE/HTB/SQM yapılandırması varsayılan olarak asla ezilmez.

Çakışmayan adayların birleşimi de sınanır; birleşime tek başına eşiği geçmemiş
ama kötüleşme de göstermemiş nötr adaylar katılabilir. Aynı kaynağı değiştiren
çelişkili adaylar (iki qdisc, iki coalescing) birleştirilmez.

### Yük altında düşük gecikme (SQM) — opt-in, Beta

Eski sürüm `cake`'i **bandwidth vermeden** kuruyordu. CAKE'in varsayılanı
`unlimited`'dır: shaper devre dışıdır, yalnız AQM çalışır. Darboğaz modemde
ya da ISS'te olduğunda bu kuyruğu kontrol etmez.

Gerçek kazanç için kuyruğun bizim tarafımıza çekilmesi, yani hattın gerçek
kapasitesinin biraz altında şekillendirme yapılması gerekir. Bunun bedeli
throughput'tur, bu yüzden ayrı ve varsayılan **kapalı** bir kiptir:

```bash
# Kapasiteyi hız testinizden ya da ISS sözleşmenizden girin.
# Ethernet/Wi-Fi link hızı internet kapasiteniz DEĞİLDİR.
dpi-bypass latency calibrate 20000 100000     # upload / download kbit/s
dpi-bypass set latency_sqm=true
```

- Kapasite bilinmiyorsa shaping **yapılmaz**; keyfî bir 10/100 Mbit değeri
  uydurulmaz.
- Tek bir sabit yüzde dayatılmaz: %95, %90 ve %85 oranları aday olarak
  karşılaştırılır, kazananı ölçüm seçer.
- Bütün akışlara adil davranan `besteffort` kullanılır. ICMP'ye özel öncelik
  verilmez, "tüm UDP oyundur" varsayılmaz.
- CAKE'in `rtt` parametresi bilinçli olarak ayarlanmaz: o bir AQM hedefidir,
  internet ping'ini o değere sabitlemez.
- Ingress için yalnız **uygulamaya ait** bir IFB aygıtı (`ifb-dpib`), kendi
  kök handle'ımız (`4470:`) ve kendi filter önceliğimiz (`prio 4470`)
  oluşturulur. Arayüzde zaten bir ingress/clsact yapılandırması varsa ona
  dokunulmaz ve durum açıkça **"yalnız upload şekillendirildi"** olarak
  raporlanır.
- Yük testi kapalıyken SQM adayları yalnız boşta ölçülür; bu durumda yük
  altındaki kazanç ve throughput bedeli **ölçülememiştir** ve arayüz bunu
  söyler.

Dizüstü bilgisayardaki shaping yalnız bu makinenin trafiğini kontrol eder.
Modem/ISS kuyrukları ve evdeki diğer cihazlar yönetilmez; çoğu durumda doğru
yer **router tarafındaki SQM**'dir. Bu araç router'a bağlanmaz, ayarını
değiştirmez.

### Kontrollü yük testi — opt-in

Gerçek bufferbloat ölçümü hattı doyurmayı gerektirir. Bu yalnız sizin açık
onayınızla, **size ait ya da yük testine açıkça izinli** bir sunucuya karşı ve
sert bir bütçe altında yapılır. Genel DNS çözücülerine, ölçüm referanslarına ve
oyun sunucularına yük gönderilmez — reddedilir. Ölçümlü/mobil bağlantıda ayrı
bir onay istenir. Yük hiç uygulanmadıysa sonuçta "bufferbloat ölçüldü" yazmaz.

### Kabul, veto ve geri alma

Kazanç kullanıcının hedefinde aranır. Aşağıdakilerden biri olursa aday
reddedilir ya da uygulanmış değişiklik geri alınır:

- ölçüm koşulu, yöntemi ya da hedef kimliği değişirse (karşılaştırılamaz),
- ölçüm yolu doğrulanamazsa,
- bir hedef yanıt vermeyi bırakırsa (kapsam kaybı),
- kayıp/başarısızlık oranı artarsa,
- median kazancının altında p95 ya da jitter kötüleşirse,
- bağımsız holdout doğrulamasında kazanç tekrarlanmazsa,
- aday yarım uygulanırsa (uygulanan adımların hepsi geri alınır),
- ağ/arayüz değişirse,
- tarama sırasında ayar dışarıdan değiştirilirse (tarama durur, araya giren
  ayar korunur).

Komutun `0` dönmesi "uygulandı" sayılmaz: her eylemden sonra değer **geri
okunur** ve hedef duruma ulaşılmadıysa adım başarısızdır. Bu, NetworkManager
veya güç yönetimi servisinin ayarı hemen geri değiştirdiği durumları yakalar.

Geri alma tarifi her zaman **değişiklikten önce** diske yazılır
(`/run/dpi-bypass/latency.json`), ters sırada uygulanır ve idempotenttir.
Kayıt yalnız arayüz adını değil `ifindex`'i de taşır: `eth0` adı yeniden
kullanıldığında eski kayıt farklı bir aygıta uygulanmaz. Kayıt **bozuksa**,
"kayıt yok" ile aynı sayılmaz — dosya silinmez, yeni hiçbir değişiklik
yapılmaz ve durum `snapshot-corrupt` olarak bildirilir.

### Durum kodları

`enabled` sizin tercihiniz, `active` şu anda yürürlükte ve doğrulanmış ayardır;
ikisi karıştırılmaz. Durum kodları kararlıdır ve arayüz metninden bağımsızdır:

`disabled` · `measuring` · `applying` · `benchmarking` · `verifying` ·
`active` · `no-gain` · `inconclusive` · `unsupported` · `already-configured` ·
`permission-denied` · `external-change` · `rolled-back` · `rollback-failed` ·
`snapshot-corrupt` · `failed` · `cancelled`

Her aday için ayrıca `tried` / `not-needed` / `unsupported` /
`budget-exhausted` / `rejected` / `failed` / `cancelled` ve gerçek nedeni
gösterilir. Kazanç yoksa bu bir teknik açıklamayla söylenir ("yalnız Wi-Fi
adayı denendi; mevcut kuyruk korundu; yük testi yapılmadı") — "artık daha
düşük ms mümkün değil" iddiasına dönüştürülmez.

### Ağ başına öğrenme

Doğrulanan en iyi aday ağ parmak izi ile `/var/lib/dpi-bypass/latency-profiles.json`
içinde saklanır. Kayıt yalnız "hangi adayı önce dene" bilgisidir. Ölçüm koşulu,
hedef kümesi, arayüz, çekirdek ya da şema değişirse kayıt geçersiz sayılır;
eski bir kazanç bugünün ölçümü gibi gösterilmez. Aktif profil seyrek ve hafif
biçimde denetlenir (cooldown + histerezis); sürekli doygunluk testi yapılmaz ve
doğal dalgalanmada apply/rollback salınımı kurulmaz.

### Kapsam dışı

DNS, MTU, rota, DHCP, IPv6, firewall, kalıcı sysctl, BBR, `tcp_low_latency`
(etkisiz bir legacy anahtar), GRO/GSO/TSO, ring buffer, IRQ affinity, RPS/XPS
ve CPU governor bu kipin kapsamı dışındadır. QUIC veya IPv6 bu kip adına
kapatılmaz; oyun/UDP trafiği vekile taşınmaz (vekil yalnız TCP 80/443 taşır).

### Komutlar

```bash
dpi-bypass latency status                     # aday sonuçları, önce/sonra, kazanç
dpi-bypass latency status --json              # aynısı, makine okunur
dpi-bypass latency on                         # A/B/A taramasını başlat
dpi-bypass latency off                        # kipi kapat, değişiklikleri geri al
dpi-bypass latency cancel                     # devam eden ölçümü durdur ve geri al
dpi-bypass latency test                       # yalnız ölç, hiçbir şeyi değiştirme
dpi-bypass latency test --condition first-packet
dpi-bypass latency target list|add|remove|clear
dpi-bypass latency calibrate 20000 100000     # hat kapasitesi (kbit/s)
dpi-bypass latency report                     # yerel, gizlilik korumalı tanı raporu
```

Tanı raporu yereldir: SSID, ağ geçidi MAC'i, dış IP ve hedef adlarınız rapora
konmaz.

### Kazancı kendiniz doğrulayın

Aracın kararına güvenmeniz gerekmez; aynı hedefte kendiniz A/B yapın:

```bash
dpi-bypass latency target add <kendi-hedefiniz>   # aynı hedefi sabitleyin
dpi-bypass latency off  && dpi-bypass latency test   # A: kapalı
dpi-bypass latency on   && dpi-bypass latency test   # B: açık
dpi-bypass latency off                                # her şeyi geri al
```

Tek bir ölçüme bakmayın; birkaç kez tekrarlayın ve **aynı** hedefe, **aynı**
koşulda baktığınızdan emin olun. Farklı hedefleri karşılaştırmak ya da DNS
süresini oyun RTT'si sanmak yanıltır.

## Vodafone sınırsız modu

Vodafone'un "Red Sınırsız" tarifelerinde mobil veri sınırsızdır, ancak
**hotspot/tethering 15 GB ile sınırlıdır**. Operatör paylaşımı paketin **TTL**
(IPv6'da hop limit) değerinden anlar: telefonun kendi trafiği operatöre `64`
ile ulaşır, laptoptan gelen paket ise telefonda bir kez yönlendirildiği için
`63` olarak varır ve kotadan düşer.

Bu mod, bu bilgisayardan çıkan paketleri **TTL 65** ile yollar. Telefon bir
düşürünce operatöre tam `64` gider.

**Nasıl açılır:** Ayarlar → Gelişmiş → *Vodafone sınırsız modu*. Açarken
polkit üzerinden **yönetici parolası** sorulur. Komut satırından:

```bash
dpi-bypass vodafone status     # durum + paket sayacı
dpi-bypass vodafone on
dpi-bypass vodafone off
```

**Yalnızca kaydedildiği ağda çalışır.** Modu açtığınız andaki ağın parmak izi
kaydedilir; ev Wi-Fi'ına ya da Ethernet'e geçtiğinizde kural kendiliğinden
kalkar, telefona döndüğünüzde geri gelir. Kurallar `inet dpibypass_ttl`
tablosunda, `oifname` ile yalnızca ilgili arayüze bağlı olarak tutulur.

**Atlatma bozulmaz.** `disorder` ve `fake` stratejileri kasıtlı olarak düşük
TTL'li (2-8) paketler gönderir; bu paketlerin DPI'ı geçip sunucuya
*ulaşmaması* atlatmanın çalışma ilkesidir. Bu yüzden TTL yeniden yazımı
yalnızca TTL'i **32'nin üstünde** olan paketlere uygulanır. Eşik, bir test
(`test_ttl_guard_desync_stratejilerinin_uzerinde`) ile korunur: ileride daha
yüksek TTL'li bir strateji eklenirse test kırmızıya döner.

**IPv6.** Telefon tethering yaparken laptopa kendi global IPv6 adresini verir;
o zaman operatör aynı aboneden iki farklı IPv6 kaynağı görür ve hop limit ne
olursa olsun paylaşım anlaşılır. Bu yüzden mod, varsayılan olarak yalnızca
tethering arayüzünde IPv6'yı kapatır (`vodafone_disable_ipv6`) ve kapanırken
eski değeri geri yazar.

> **Polkit kapısı hakkında dürüst not:** `dpi-bypass` grubundaki bir kullanıcı
> zaten denetim soketine doğrudan `vodafone.enable` komutu yollayabilir. Yani
> parola sorma adımı **teknik bir güvenlik sınırı değildir**; sistem genelinde
> paket başlığı değiştiren bir ayarın yanlışlıkla ya da fark edilmeden
> açılmasını engelleyen bilinçli bir onay adımıdır.

> **Kullanım koşulları uyarısı:** Bu mod, operatör sözleşmenizin kullanım
> koşullarına aykırıdır. Otomatik sayacı atlatır, ancak çok yüksek kullanım
> (ayda yüzlerce GB üzeri) adil kullanım incelemesine takılabilir — orada
> TTL'in bir etkisi olmaz. Sorumluluk kullanıcıya aittir.

Kuralın gerçekten çalıştığını görmek için:

```bash
sudo nft list table inet dpibypass_ttl
sudo tcpdump -ni <arayüz> -v -c 5 'tcp port 443' | grep -o 'ttl [0-9]*'
```

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
dpi-bypass vodafone status  # hotspot TTL düzeltmesi (on / off)
dpi-bypass latency status   # Ping düşürme (on/off/test/target/calibrate/report/cancel)
dpi-bypass doctor           # soket erişimi tanısı (grup / oturum / soket)
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

### Denetim soketi ve grup erişimi

Servis `/run/dpi-bypass/daemon.sock` üzerinden yönetilir. Soket **root:dpi-bypass
/ 0660** olarak kurulur ve bu gerçekten uygulanıp uygulanmadığı `stat` ile
yeniden okunarak doğrulanır. Grup çözülemez ya da izinler uygulanamazsa soket
herkese açılmaz; yalnız root'a bırakılır (`0600`) ve servis günlüğüne hata
yazılır.

"Erişim reddedildi" hatasının tek bir sebebi yoktur; `dpi-bypass doctor` hangisi
olduğunu söyler:

| Durum | Anlamı | Çözüm |
|---|---|---|
| `group-missing` | `dpi-bypass` grubu sistemde yok | `sudo groupadd --system dpi-bypass` |
| `not-a-member` | Kullanıcı grup veritabanında üye değil | `sudo usermod -aG dpi-bypass $USER` ya da arayüzdeki **Erişimi onar** |
| `stale-session` | Kullanıcı üye ama **açık oturum** eski grup listesinde | Uygulama kendini `sg dpi-bypass -c …` ile yeniden başlatır |
| `no-socket` | Servis çalışmıyor | `sudo systemctl start dpi-bypass` |
| `socket-permissions` | Soketin grubu/kipi beklenenden farklı | `sudo systemctl restart dpi-bypass` |

`usermod -aG` **çalışan süreçlerin** ek gruplarını değiştirmez; bu yüzden
kurulumdan sonra grup eklense bile açık masaüstü oturumu eski listeyi taşır.
GUI ve komut satırı bu durumu ayırt eder ve `sg` ile bir kez (döngü koruması
ile) kendini yeniden başlatır — oturum kapatmak ya da yeniden başlatmak
gerekmez. `sg` yoksa bu açıkça söylenir.

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
| `latency_mode` | `false` | Ölçümlü düşük gecikme optimizasyonu |
| `latency_targets` | `[]` | Kendi ölçüm hedefleriniz; boşsa genel ağ göstergesi kullanılır ve öyle etiketlenir |
| `latency_sqm` | `false` | Yük altında düşük gecikme (gerçek shaping). Throughput'tan feragat eder |
| `latency_uplink_kbit` | `0` | Hat upload kapasitesi (kbit/s). `0` = bilinmiyor, shaping yapılmaz |
| `latency_downlink_kbit` | `0` | Hat download kapasitesi (kbit/s) |
| `latency_max_throughput_loss` | `15.0` | SQM'de kabul edilen azami throughput kaybı (%) |
| `latency_load_test` | `false` | Kontrollü yük testi. Yalnız size ait/izinli bir sunucuya |
| `latency_load_target` | `{}` | Yük testi sunucusu (`host`, `port`, `mode`, `owned`) |
| `latency_load_max_seconds` | `12` | Yük testi süre bütçesi (sert üst sınır 60) |
| `latency_load_max_bytes` | `67108864` | Yük testi veri bütçesi (sert üst sınır 512 MB) |
| `latency_metered` | `false` | Bağlantı ölçümlü/mobil; yük testi için ayrı onay ister |
| `vodafone_mode` | `false` | Vodafone sınırsız modu (hotspot TTL düzeltmesi) |
| `vodafone_networks` | `[]` | Modun etkin olacağı ağlar (en fazla 10) |
| `vodafone_ttl` | `65` | Giden paketlere yazılacak TTL (ileri düzey) |
| `vodafone_disable_ipv6` | `true` | Tethering arayüzünde IPv6'yı kapat |

Öğrenilen ağlar ve alan adları: `/var/lib/dpi-bypass/state.json`

---

## Gereksinimler

- Linux, systemd
- Python 3.8+
- nftables (yoksa iptables)
- iproute2/`tc` ve `ip`, `iw`, `ethtool` (Ping düşürme adayları ve rota doğrulama; yoksa güvenle atlanır)
- `sg` (shadow-utils) — grup üyeliği yeni eklendiğinde oturum kapatmadan uygulanır
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
  latency/       ölçümlü düşük gecikme motoru
    metrics.py   endpoint bazında örnek ve özet (havuzlama yok)
    probe.py     hedef çözümleme, yol doğrulama, protokol başına örnekleme
    analysis.py  eşleştirilmiş A/B karşılaştırması ve blok bootstrap
    qdisc.py     yapılandırılmış kuyruk keşfi ve kanıtlanmış geri alma
    sqm.py       gerçek bandwidth shaping + IFB ingress (opt-in)
    load.py      izinli, bütçeli kontrollü yük üretimi (opt-in)
    actions.py   uygula → geri oku → kanıtla → geri al
    profiles.py  ağ başına öğrenilen aday ve geçerlilik denetimi
    engine.py    akışın düzenleyicisi
  session_access.py  grup / oturum / soket erişim tanısı ve 'sg' onarımı
  vodafone.py    hotspot TTL düzeltmesi (ayrı tabloda, eşik korumalı)
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
