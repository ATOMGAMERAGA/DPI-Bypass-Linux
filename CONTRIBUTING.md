# Katkı rehberi

DPI Bypass'a katkı gönderirken değişikliğin küçük, doğrulanabilir ve geri
alınabilir olması tercih edilir. Özellikle ağ, firewall, systemd ve polkit
gibi ayrıcalıklı alanlara dokunan değişiklikler için davranışı sabitleyen test
eklenmesi önemlidir.

## Geliştirme ortamı

Çekirdek testlerin büyük bölümü yalnızca Python standart kütüphanesini
kullanır. Projenin kurulum betiği Python 3.8 ve üzerini desteklediğinden yeni
kod da bu alt sınırı korumalıdır.

Yerel doğrulama için:

```bash
python3 -m compileall -q src tests
python3 -m unittest discover -s tests -v
bash -n install.sh
```

GTK/libadwaita kurulu olmayan geliştirme makinelerinde GUI testleri proje içi
stub'ları kullanır; testler gerçek masaüstü oturumu veya internet bağlantısı
gerektirmemelidir.

Ağ veri yolunu gerçekten çalıştıran entegrasyon testleri ayrıdır ve varsayılan
olarak atlanır. Root yetkisi, `ip` ve `tc` gerektirir; ana makinenin fiziksel
NIC'ine, default route'una veya firewall'una dokunmaz:

```bash
sudo DPIBYPASS_NETNS_TESTS=1 python3 -m unittest tests.test_netns_latency -v
```

Atlanan bir entegrasyon testi **geçmiş sayılmaz**. Bir performans iddiası için
mock testlerin geçmesi tek başına yeterli değildir; simüle edilmiş bir ağda
ölçülen kazanç da kullanıcının hattında ölçülmüş gibi sunulamaz.

## Test ilkeleri

- Yeni hata düzeltmeleri mümkünse önce aynı hatayı yeniden üreten bir regresyon
  testiyle güvence altına alınmalıdır.
- Unit testler gerçek dış ağa, gerçek ISP'ye veya belirli bir DNS sağlayıcısına
  bağımlı olmamalıdır.
- Root yetkisi gerektiren komutlar doğrudan çalıştırılmamalı; `unittest.mock`
  ile süreç, soket veya sistem aracı sınırı taklit edilmelidir.
- Geçici dosya kullanan testler kendi dizinlerini oluşturup temizlemelidir.
- Ağ ve sistem yapılandırmasını değiştiren kod için başarısızlık ve geri alma
  yolları ayrıca test edilmelidir.

## Kod değişiklikleri

- Python kodunda mevcut modül yapısını ve `from __future__ import annotations`
  kullanımını koruyun.
- Yeni sabitleri mümkün olduğunda `constants.py` içinde merkezileştirin.
- Kullanıcıdan veya sistem komutlarından gelen değerleri shell metnine doğrudan
  birleştirmeyin; mevcut yardımcı fonksiyonları ve doğrulama katmanlarını
  kullanın.
- Log mesajlarında erişim anahtarı, oturum bilgisi veya gereksiz ağ kimliği
  tutmayın.
- Kurulum, systemd veya polkit değişikliklerinde en azından sözdizimi ve
  geriye dönük uyumluluk kontrolü ekleyin.

## Pull request kontrol listesi

PR açmadan önce aşağıdakileri doğrulayın:

- [ ] `python3 -m unittest discover -s tests -v` başarılı.
- [ ] `python3 -m compileall -q src tests` başarılı.
- [ ] `bash -n install.sh` başarılı.
- [ ] Yeni davranış için test eklendi veya test gerekmemesinin nedeni açıklandı.
- [ ] Değişiklik mevcut kullanıcı yapılandırmalarını gereksiz yere sıfırlamıyor.
- [ ] PR açıklamasında kullanıcıya görünen etkiler ve olası riskler belirtildi.

CI, desteklenen Python aralığının alt ve güncel sürümlerinde bu temel kontrolleri
otomatik olarak çalıştırır.
