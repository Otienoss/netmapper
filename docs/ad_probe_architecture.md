# Zero False-Positive AD Probe Mimarisi

Bu altyapı check-only AD kontrolleri içindir. Amaç, “test çalışmadı” ile
“zafiyet yok” sonuçlarını birbirinden ayırmak ve yalnızca deterministik kanıtla
sınıflandırma yapmaktır.

## Paket

- `app/ad_probes/models.py`: beş sonuç seviyesi, pre-flight/evidence/cleanup modelleri
- `app/ad_probes/preflight.py`: salt-okunur LDAP ön-keşif
- `app/ad_probes/base.py`: `BaseADProbe` yaşam döngüsü
- `app/ad_probes/verifiers.py`: ccache, Kerberos DER ve RPC durum kodu kontrolleri
- `app/ad_probes/cleanup.py`: dosya/LDAP silme sonrası bağımsız doğrulama
- `app/ad_probes/maq.py`: örnek `MachineAccountQuotaProbe`
- `app/services/ad_probe_runner.py`: `job_manager` adaptörü

## Yaşam döngüsü

```text
discovery() → pre_check() → minimal_trigger() → verify_proof() → cleanup()
```

`BaseADProbe.run()` tüm aşamaları asenkron koşar. `minimal_trigger` ve
`verify_proof` soyuttur; her modül kendi sınırlı testini ve kanıt eşiğini
tanımlar. `cleanup()` erken çıkışta ve hata durumunda da çalışır.

## Sonuç semantiği

| Sonuç | Anlam |
|---|---|
| `exploited` | **Pasif/rezerv:** check-only modüller bu değeri DÖNDÜRMEZ; yalnızca ileride durum değiştiren kanıt türleri için ayrılmıştır |
| `validated` | İstenen ön koşul/zafiyet davranışı deterministik kanıtla doğrulandı |
| `attempted` | Tetik başladı fakat kanıt aşamasına ulaşılamadı |
| `inconclusive` | Veri toplanamadı veya kanıt doğrulanamadı; olumsuz bulgu DEĞİL |
| `failed` | Açık ön koşul ihlali; tetik hiç çalıştırılmadı |

Örneğin MAQ=0 `failed`, MAQ okunamaması `inconclusive` olur. İkisi de
`minimal_trigger` çağrılmadan döner.

## Pre-flight verileri

`PreflightEngine`, tek LDAP oturumunda şunları toplar:

- Hedef DC `sAMAccountName` ve `dNSHostName`
- Domain `objectSid` (`S-1-5-21-...` biçimine çevrilir)
- `ms-DS-MachineAccountQuota`
- Kerberos süreleri (`maxTicketAge`, `maxRenewAge`, `maxServiceAge`,
  `maxClockSkew`; 100-ns değerler dakikaya çevrilir)
- DC `msDS-SupportedEncryptionTypes`

Birden fazla DC kaydı varken hedef tekil kayıtla eşleşemiyorsa ilk kayıt
seçilmez; sonuç `inconclusive` olur. Bu durumda API isteğinde `target_dc`
(veya `dc_fqdn` alias'ı) ile FQDN, kısa hostname ya da `sAMAccountName`
zorunlu gösterilebilir. Açık seçici yanlışsa tek kalan başka DC'ye bile
sessizce fallback yapılmaz.

## Katı async timeout

`PreflightEngine.collect()` blocking LDAP iş parçacığını `asyncio.wait_for`
ile sınırlar; ayrıca LDAP socket `connect_timeout`/`receive_timeout` değerleri
uygulanır. `BaseADProbe.stage_timeouts` beş aşamanın her birini ayrı
`asyncio.wait_for` ile çalıştırır. Trigger zaman aşımı `attempted`, discovery
veya verification zaman aşımı `inconclusive`, cleanup zaman aşımı
`cleanup.status=unverified` olur. Böylece ağ donması job'ı sonsuza kadar
askıda bırakmaz.

## Kanıt kontrolleri

- **ccache:** `0x0504` magic, header uzunluğu ve dosya sınırı.
- **Kerberos ASN.1/DER:** APPLICATION mesaj türü, DER uzunluk ve yanıt sınırı.
  Yapısal doğrulama tek başına erişim kanıtı sayılmaz.
- **RPC:** NTSTATUS/HRESULT değerleri sayısal olarak karşılaştırılır; metin
  loglarına güvenilmez.

## Cleanup

`cleanup_files_verified()` silme sonrası dosya/dizin yokluğunu yeniden kontrol
eder. `cleanup_ldap_object_verified()` bağımsız `delete` ve `exists`
fonksiyonlarıyla delete → re-query akışı uygular. Yeniden sorgu yapılamazsa
`cleanup.status=unverified` döner; temizlik hatası ana probe sonucunu ezmez.

## WebSocket / job payload sanitizasyonu

`app/core/sanitizer.py`, bilinen parola/token değerlerini, sensitive dict
anahtarlarını, Bearer/Authorization değerlerini, Kerberos hash kalıplarını ve
NTLM hash çiftlerini maskeler. `job_manager.log()` mesajı kaydetmeden önce,
`job_manager.serialize()` ise HTTP job detail ve WebSocket payload'ını
yayınlamadan önce sanitizasyon uygular. Ham kanıt dosyaları ve DB bulguları
değiştirilmez; maskeleme dışa giden kopya üzerinde yapılır. Ham iş sırları
terminal job durumunda bellekten de silinir.

## FastAPI / job_manager

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ad/probe \
  -H 'Content-Type: application/json' \
  -d '{"target":"10.0.0.5","domain":"corp.local",
       "username":"alice","password":"sifre","probe":"maq",
       "target_dc":"dc01.corp.local"}'
```

İş `module="ad_probe"` olarak başlar. Sonuç `GET /api/v1/jobs/{job_id}` altında
`results[0]` olarak bulunur; ilerleme ve sonuç özeti WebSocket loglarına da
yazılır. Parola `JobState.meta`, DB veya sonuç JSON'una yazılmaz.
