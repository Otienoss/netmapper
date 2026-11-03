# ARP Güvenlik ve Postür Analizi

Bu modül ARP zehirlenmesine zemin hazırlayan kontrol eksiklerini savunma
amaçlı olarak raporlar. **Ağa paket göndermez**, ARP tablosu değiştirmez,
IP forwarding açmaz veya trafiği kendi üzerine yönlendirmez.

## Bileşenler

- `app/arp_security/config_audit.py`: Cisco IOS benzeri switch
  konfigürasyonlarında DHCP snooping, DAI, IP Source Guard, port security ve
  802.1X kontrollerini denetler.
- `app/arp_security/analyzer.py`: ARP olaylarından gateway MAC çakışması,
  IP-MAC flap, duplicate MAC ve gratuitous ARP burst bulguları üretir.
- `app/arp_security/monitor.py`: Scapy `sniff` ile yalnızca pasif dinleme;
  `send`, `sendp`, `srp` veya forwarding değişikliği içermez.
- `app/arp_security/pcap.py`: Yetkili offline PCAP/PCAPNG kayıtlarını akış
  halinde analiz eder; payload yerine yalnızca ARP metadata'sı kullanılır.

## Arayüzden kullanım

Dashboard üst sekmelerinde **🛰 ARP Güvenlik** bulunur:

1. **Canlı Pasif ARP Monitörü:** Interface, isteğe bağlı gateway baseline,
   süre ve paket limiti seçilir. “Pasif İzlemeyi Başlat” ile job açılır;
   canlı loglar WebSocket üzerinden gelir, “Durdur” ile analiz tamamlanır.
2. **Offline PCAP Analizi:** Yetkili PCAP seçilip “PCAP'i Analiz Et”e basılır.
   Monitör bölümündeki gateway alanları baseline olarak kullanılır.
3. **Switch Konfigürasyon Denetimi:** Konfigürasyon metni yapıştırılır.
   Kısmi metinde eksik kontroller `unknown`, tam metin işaretlenirse `fail`
   olur. Bulgular kanıt ve remediation sütunlarıyla listelenir.

Panel: `app/static/panels/arp_guvenlik.html`; istemci mantığı:
`app/static/arp_guvenlik.js`.

## API

### Switch konfigürasyon denetimi

```bash
curl -X POST http://127.0.0.1:8000/api/v1/arp/config-audit \
  -H 'Content-Type: application/json' \
  -d '{"config_text":"ip dhcp snooping\nip arp inspection vlan 10",
       "config_complete":false}'
```

Kısmi konfigürasyonda eksik kontrol `unknown` olur; olumsuz bulgu sayılmaz.
`config_complete=true` yalnızca tam konfigürasyon verildiğinde kullanılmalıdır.

### Pasif ARP monitörü

```bash
curl -X POST http://127.0.0.1:8000/api/v1/arp/monitor/start \
  -H 'Content-Type: application/json' \
  -d '{"interface":"eth0","gateway_ip":"192.168.1.1",
       "duration_sec":60,"max_packets":5000}'

curl -X POST http://127.0.0.1:8000/api/v1/arp/monitor/stop/JOB_ID
```

Monitör `module="arp_monitor"` olarak mevcut job/WebSocket akışını kullanır.
Pasif dinleme işletim sistemine göre root/capture yetkisi gerektirebilir.

### Offline PCAP analizi

```bash
curl -X POST http://127.0.0.1:8000/api/v1/arp/pcap-audit \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @authorized-capture.pcap
```

Gövde `application/octet-stream` olarak akışla okunur. Boyut sınırı 25 MiB;
geçici dosya analizden sonra her koşulda silinir. İsteğe bağlı `gateway_ip`
ve `gateway_mac` sorgu parametreleri baseline kontrolü sağlar.

## Sonuç durumları

- `clean`: Yeterli veri var, tanımlı anomali bulunamadı.
- `alerts`: En az bir kanıtlı anomali var; her alert kanıt ve remediation içerir.
- `inconclusive`: Yeterli ARP verisi yok veya belirtilen gateway görülmedi;
  “güvenli” anlamına gelmez.

HA/VRRP/HSRP, DHCP adres devri ve anycast gibi meşru davranışlar bazı
anomalilere yol açabilir. Bulgular switch CAM/DHCP binding kayıtlarıyla
doğrulanmalıdır.
