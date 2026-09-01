# Ping düşürme: tasarım ve doğrulama notları

Bu belge motorun **neden** böyle kurulduğunu ve bir iddianın hangi kanıta
dayandığını anlatır. Kullanım için `README.md` içindeki "Ping düşürme (Beta)"
bölümüne bakın.

## 1. Çözülen iki somut ölçüm hatası

Motorun yeniden yazılmasının nedeni iki doğrulanmış karşı örnektir. İkisi de
`main` dalının `98f9be5` commit'inde sentetik veriyle yeniden üretildi.

### 1.1 Hedef ağırlığının kayması sahte kazanç üretiyordu

İki hedef: A her zaman 10 ms, B her zaman 100 ms. Her hedefe 16 deneme.
Önce A'dan 8, B'den 16 yanıt; sonra A'dan 16, B'den 8 yanıt. İki tarafta da
toplam kayıp `%25` ve **hiçbir hedefin RTT'si iyileşmiyor**.

Eski motor bütün örnekleri tek havuzda birleştirdiği için:

```
birleşik median: 100 ms → 10 ms      evaluate() → (True, "doğrulandı")
```

Yani ölçülen değil, *uydurulan* bir kazanç. Bugün aynı veri:

```
toplu median: 55 ms → 55 ms          compare() → no-gain
```

**Düzeltme:** `metrics.py` içinde her endpoint kendi `sent`/`received`
sayısını ve kendi özetini taşır. Toplu gösterge hedef başına *eşit
ağırlıklıdır*. Karar ise `analysis.py` içinde endpoint bazında ve
eşleştirilmiş bloklarla verilir; hiçbir aşamada havuzlama yoktur.
Yavaş hedefin susması `coverage` düşüşü olarak görünür ve iyileşme değil
**kötüleşme** sayılır.

Regresyon testi: `TestAnalysis.test_response_weight_shift_is_not_a_gain`,
`TestMetrics.test_aggregate_is_weighted_per_endpoint_not_per_sample`.

### 1.2 Gerçek ama küçük kazançlar eşiğe takılıyordu

Eski eşikler median için `max(2 ms, %5)` idi. Tekrarlanan, sistematik bir
`10 → 9 ms` iyileşme bu duvara takılıp "kazanç yok" sayılıyordu.

**Düzeltme değil-yapılan:** eşiği sıfırlamak. Bu yalnız yanlış pozitifleri
artırırdı.

**Yapılan:** ölçüm tasarımını düzeltmek. Karar artık blok çiftlerinin
farkları üzerinden hesaplanan **blok bootstrap güven aralığına** dayanır.
Yeterli bağımsız tekrar ve ölçüm çözünürlüğü varsa 1 ms altındaki bir kazanç
da değerlendirilebilir; yoksa hiçbir büyüklükteki fark kabul edilmez.

Regresyon testleri:
`test_small_but_repeated_improvement_is_accepted`,
`test_sub_millisecond_improvement_can_be_evaluated`,
`test_noise_below_the_resolution_is_not_a_gain`.

## 2. Neden A/B/A ve neden bootstrap

Tek bir başlangıç baseline'ına karşı ölçüm yapmanın iki hatası var:

* **Sürüklenme (drift).** Ağ ölçüm boyunca kendiliğinden iyileşirse bu kazanç
  sıradaki adaya yazılır.
* **Sıra etkisi.** Adaylar hep aynı sırayla denenirse sonraki adaylar
  sistematik olarak avantajlı ya da dezavantajlı olur.

Motor bunun yerine **ABBA blokları** kullanır: her B ölçümü komşusundaki A
ölçümüyle eşleştirilir ve sıra bloklar arasında dengelenir. Bağımsız birim
tek paket değil, **blok çiftidir** — ardışık ve birbiriyle korelasyonlu
paketleri binlerce bağımsız gözlem saymak güven aralığını sahte biçimde
daraltırdı.

### Gürültü tabanı (A/A kapısı)

`control_noise()` kontrol kolunu tek/çift diye ikiye böler ve **aynı ayarla**
alınmış bu iki yarıya adaya uyguladığı prosedürün aynısını uygular. Çıkan
fark, hiçbir şey değiştirmeden bile görülebilen gürültüdür.

Bu taban **iki yönü de** kapılar:

* `improved` olması için `|ortalama fark| >= max(pratik_asgari, gürültü)`,
* `regressed` olması için `GA_alt > max(tolerans, gürültü)`.

Böylece A/A verisinde ne sistematik bir kazanan seçilir ne de gürültü
"kötüleşme" diye raporlanır. Gürültü tabanı pratik asgarinin belirgin
üstündeyse sonuç `no-gain` değil **`inconclusive`** olur: o koşulda o
büyüklükte bir kazanç zaten ölçülemezdi ve "kazanç yok" demek dürüst olmazdı.

Regresyon testleri: `test_pure_noise_never_produces_a_systematic_winner`
(6 farklı seed), `test_natural_drift_is_not_credited_to_the_candidate`.

### Holdout

Çok adaylı bir tarama, yeterince aday denenirse tesadüfen "kazanan" üretir.
Bu yüzden tarama kazananı, **taramada kullanılmamış yeni bloklarla** yeniden
sınanır (`_optimize_inner` → holdout). Eski baseline'a karşı B'yi tekrar
ölçmek bu değildir ve yeterli değildir.

## 3. Veto sırası

Kötüleşme her zaman kazançtan önce değerlendirilir:

1. Karşılaştırılabilirlik (koşul, yöntem, hedef kimliği, yol doğrulaması)
2. Kapsam kaybı (bir hedef susarsa)
3. Kayıp/başarısızlık oranı artışı
4. Metrik kötüleşmesi (median / p95 / jitter)
5. Ancak bundan sonra kazanç

Median kazancının altında gizlenen bir p95 artışı bu yüzden aday reddettirir.

## 4. Kanıt olmadan "uygulandı" yok

Her mutasyon için:

```
tarifi diske yaz  →  uygula  →  GERİ OKU ve karşılaştır  →  imzayı sakla
```

Dönüş kodunun `0` olması yeterli değildir: sürücü isteği sessizce yok saymış
ya da NetworkManager/güç yönetimi ayarı hemen geri değiştirmiş olabilir. Wi-Fi
güç tasarrufu, EEE, coalescing ve qdisc — hepsi readback ile doğrulanır.

Aynı fikir kuyruk yapısında da kullanılır: bir yapının aday olabilmesi için
geri alma tarifi `tc qdisc change` ile **uygulanarak** kanıtlanır (mevcut
değerlerin aynısı yazıldığı için no-op'tur) ve durum geri okunarak
karşılaştırılır. Sürüm farkı, desteklenmeyen seçenek ya da yazılamayan alan
burada ortaya çıkar; kanıtlanamayan yapı korunur.

Regresyon testleri: `TestActions.test_return_code_zero_without_a_real_change_is_a_failure`,
`TestQdisc.test_restore_recipe_must_be_proven_before_use`.

## 5. Sahiplik ve kurtarma

* Snapshot **bozuk** ile **yok** ayrı durumlardır. Bozuksa sistemde geri
  alınmamış bir değişiklik olabilir: dosya silinmez, yeni hiçbir mutasyon
  yapılmaz, durum `snapshot-corrupt` olur.
* Kayıt `ifindex` taşır: `eth0` adı yeniden kullanıldığında eski kayıt farklı
  bir aygıta uygulanmaz.
* Geri alma ters sırada ve idempotenttir; her eylem tek tek işaretlenir.
* SQM yalnız kendi kaynaklarını yönetir: `ifb-dpib`, `4470:` handle'ı,
  `prio 4470` filtresi. Toplu `tc qdisc del`, `nft flush ruleset`,
  `iptables -F` yoktur.
* Mutasyonlar `asyncio.shield` ile korunur: iptal isteği ancak uygulanmakta
  olan adım bittikten sonra işlenir. Yarıda kesilmiş bir komutun gerçek
  sonucu bilinemeyeceği için, mutasyon bitmeden geri alma başlatılmaz.

## 6. Doğrulama katmanları

| Katman | Ne kanıtlar | Ne kanıtlamaz |
|---|---|---|
| Birim testleri (`tests/test_latency.py`) | Karar mantığı, ayrıştırma, sahiplik, geri alma | Gerçek bir NIC'te ölçülen gecikme |
| Namespace düzeneği (`tests/test_netns_latency.py`) | Trafiğin uygulanan kuyruktan geçtiği, shaping'in yük altında p95'i düşürdüğü, geri almanın yapılandırmayı birebir kurduğu | Kullanıcının ISS'sinde ölçülmüş kazanç |
| Kullanıcının kendi A/B'si | Kendi hattındaki gerçek etki | Her kullanıcıda aynı sonuç |

Namespace düzeneği **varsayılan olarak atlanır** ve atlanan bir test geçmiş
sayılmaz:

```bash
sudo DPIBYPASS_NETNS_TESTS=1 python3 -m unittest tests.test_netns_latency -v
```

Düzenek üç namespace kurar: istemci → **darboğaz** → hedef. Darboğaz
namespace'i kasıtlıdır — gerçek hayatta modem/ISS kuyruğu bizim kontrolümüzde
değildir ve yalnız istemcideki tek kuyruğu ölçüp "bütün interneti modelledik"
demek yanlış olurdu. Ana makinenin fiziksel NIC'ine, default route'una ve
firewall'una dokunulmaz; bütün kaynaklar `dpib-` önekli ve tam kimliklidir.

Düzenekte ölçülen kazanç **simüle edilmiş** bir ağa aittir ve kullanıcının
hattında ölçülmüş gibi sunulamaz.

## 7. Bilerek yapılmayanlar

`tcp_low_latency` etkisiz bir legacy anahtardır. BBR bir TCP tıkanıklık
denetimi algoritmasıdır ve genel bir UDP/oyun RTT çözümü değildir.
GRO/GSO/TSO, ring buffer, IRQ affinity, RPS/XPS ve CPU governor'ın topluca
değiştirilmesi bir "tweak paketi"dir, ölçüm değil. Sıfır coalescing her
durumda en iyi değildir: küçük paket gecikmesi kazancının karşısında
interrupt/CPU maliyeti vardır, bu yüzden birkaç nokta denenir ve kazananı
ölçüm seçer.

QUIC ve IPv6 bu kip adına kapatılmaz. Oyun/UDP trafiği vekile taşınmaz —
vekil yalnız TCP 80/443 taşır ve oradaki bir açılış kazancı otomatik olarak
"oyun ping'i düştü" anlamına gelmez.

## 8. Bilinen sınırlar

* Dizüstü tarafındaki shaping yalnız bu makinenin trafiğini kontrol eder.
  Modem/ISS kuyrukları ve evdeki diğer cihazlar yönetilmez; doğru yer çoğu
  zaman router tarafındaki SQM'dir. Bu araç router'a bağlanmaz.
* Yük testi kapalıyken SQM adayları yalnız boşta ölçülür; yük altındaki kazanç
  ve throughput bedeli o durumda **ölçülmemiştir**.
* EEE ve coalescing'in etkisi çoğu ağda mikrosaniye düzeyindedir. Uzak RTT
  testinin çözünürlüğü bunu güvenilir biçimde ayırt etmeye yetmeyebilir; motor
  böyle bir durumda kazanç iddia etmez.
* p95/p99 iddiası için yeterli örnek yoksa bu açıkça işaretlenir
  (`p95_reliable = false`).
* Gateway ICMP'sinin cevap vermemesi ya da yavaş olması tek başına ağ
  kaybı/yerel darboğaz kanıtı değildir; teşhis tek sayıya dayandırılmaz.
