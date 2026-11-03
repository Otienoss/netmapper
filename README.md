# NetMapper

Modüler ağ keşfi ve port tarama aracı. FastAPI + asyncio subprocess ile
çalışır; `netdiscover` ile canlı host keşfi, `nmap` ile port/servis
taraması yapar, sonuçları normalize edip SQLite'a yazar ve ReportLab ile
PDF risk raporu üretir.

> ⚠️ **Yetki uyarısı:** Bu araç artık **herhangi bir IP/CIDR** kabul eder
> (private kısıtı kaldırıldı; tek sınır en fazla /24 genişlik). Yine de
> yalnızca **sahip olduğunuz veya yazılı izin aldığınız** ağlarda
> çalıştırın — izinsiz tarama birçok ülkede yasal olmayabilir.

## Kurulum

```bash
cd netmapper
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # AD modülü için: impacket, bloodhound, networkx
# Sistem araçları (Debian/Ubuntu):
sudo apt install nmap netdiscover nikto
# bloodhound-python CLI'sı PATH'te olmalı (pip user kurulumu: ~/.local/bin)
```

> `nikto` yoksa tarama yine çalışır; loglara "nikto kurulu değil — atlandı"
> düşer. Nikto, **Tam Tarama** profilinde nmap ile **aynı anda** başlar
> (kör web port seti: `settings.nikto_ports`), Özel profilde ise nmap'in
> bulduğu web portlarında çalışır.

## Çalıştırma

### Otomatik root yetkisiyle (Linux)

```bash
chmod +x start_netmapper.sh
./start_netmapper.sh
```

Script root değilse kendisini `sudo` ile yeniden başlatır, `.env` dosyasını okur
ve varsayılan olarak yalnızca **`127.0.0.1:8000`** adresini dinler. İlk
çalıştırmada `.venv` sanal ortamını oluşturup `requirements.txt` bağımlılıklarını
kullanıcı olarak kurar; root aynı venv Python'unu kullanır. Geliştirme için
`RELOAD=1 ./start_netmapper.sh`, farklı adres/port için
`HOST=... PORT=... ./start_netmapper.sh` kullanılabilir.

> **Güvenlik:** Tüm uygulamayı root çalıştırmak saldırı yüzeyini büyütür.
> Uzak arayüz (`0.0.0.0` veya başka bir IP) açmadan önce `API_TOKEN`
> tanımlayın. Sömürü modülü yalnızca izinli laboratuvarlarda kullanılmalıdır.

```bash
uvicorn app.main:app --reload
# Web arayüzü: http://127.0.0.1:8000/   (IP gir → Tara)
# API belgeleri: http://127.0.0.1:8000/docs
```

### Web arayüzü — NetMapper Dashboard

`http://127.0.0.1:8000/` adresinde 3 panelli dashboard açılır
(`NetMapper Dashboard.html` tasarımı birebir korunmuştur — `app/static/`):

1. **Dashboard** — özet kartlar (Son Tarama / Canlı Host / Açık Port /
   Yüksek Riskli Cihaz), tıklanabilir **ağ haritası** (SVG, risk renkli),
   son taramalar listesi + PDF linkleri. Besleyen uçlar: `/api/v1/stats`,
   `/api/v1/scans`, `/api/v1/scans/{id}/results`.
2. **Yeni Tarama** — subnet girişi + profil seçimi
   (Hızlı Keşif / Tam Tarama / Özel) + port listesi. Başlat deyince
   `POST /api/v1/scan` → **WebSocket** (`/api/v1/ws/jobs/{id}`) ile canlı
   ilerleme: 3 aşamalı ilerleme çubukları, anlık log konsolu, bitince
   PDF/Envanter/Dashboard linkleri. WS koparsa otomatik polling'e düşer.
3. **Host Envanteri** — tablo (IP, Hostname/Vendor, portlar, servisler,
   renkli risk rozeti), satıra tıklayınca genişleyen servis detayı,
   arama + risk filtresi, "PDF İndir". Besleyen uç: `/api/v1/hosts`.

Notlar:
- **Tek IP denemesi** (ör. `{"subnet": "192.168.1.10"}`) root'suz çalışır:
  keşif atlanır, doğrudan `nmap -sT` yapılır.
- **Alt ağ keşfi** (`netdiscover`) ham soket (AF_PACKET) gerektirir →
  subnet taraması için `sudo uvicorn app.main:app` ile başlatın.

## API Kullanımı

### Kimlik doğrulama (API_TOKEN)

Uzak erişimde **`API_TOKEN` ayarlamak zorundasınız** (bkz. `.env.example`):

```bash
export API_TOKEN="$(openssl rand -hex 32)"
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- Token tanımlıysa tüm `/api/v1/*` uçları token ister:
  `X-API-Token: <token>` header'ı **veya** `Authorization: Bearer <token>`.
- WebSocket: `ws://…/api/v1/ws/jobs/<id>?token=<token>` (tarayıcılar WS'te
  header set edemez). Yetkisiz bağlantı **4401** ile kapatılır.
- UI (paneller) `static/token.js` ile 401 alınca operatöre token sorar ve
  `localStorage`'da saklar; arayüz normal çalışmaya devam eder.
- `/health` ve statik dosyalar auth dışındadır (liveness + kabuk).
- Token tanımlı **değilse** davranış değişmez (yalnızca localhost) — ancak
  sunucu açılışında uyarı basılır. **EXPLOIT_ENABLED bir kimlik doğrulama
  mekanizması DEĞİLDİR**; sömürü kapıları API_TOKEN'dan BAĞIMSIZ ikinci
  katmandır.

```bash
# 1) Tarama başlat — profil: quick | full | custom (custom'da ports zorunlu)
curl -X POST http://127.0.0.1:8000/api/v1/scan \
     -H "Content-Type: application/json" \
     -d '{"subnet": "192.168.1.0/24", "profile": "full"}'
# -> {"job_id": "ab12...", "status": "started",
#     "ws_url": "/api/v1/ws/jobs/ab12...", "detail_url": "/api/v1/jobs/ab12..."}

# 2) Canlı ilerleme — WebSocket (polling yok):
#    ws://127.0.0.1:8000/api/v1/ws/jobs/{job_id}
#    Örnek mesaj:
#    {"status":"scanning","progress":{"hosts_total":14,"hosts_scanned":9},
#     "logs":["[10:41:02] nmap start → 192.168.1.12"], ...}
#    status done/error olduğunda bağlantı kendiliğinden kapanır.

# 3) REST durum sorgusu (WS yoksa):
curl http://127.0.0.1:8000/api/v1/jobs/ab12...
# -> {"status": "scanning", "progress": {...}, "logs": [...], ...}

# 4) Sonuçlar (JSON+risk) ve PDF:
curl http://127.0.0.1:8000/api/v1/scans/ab12.../results
curl -OJ http://127.0.0.1:8000/api/v1/scans/ab12.../report

# 5) Dashboard uçları:
curl http://127.0.0.1:8000/api/v1/stats
curl http://127.0.0.1:8000/api/v1/scans
curl http://127.0.0.1:8000/api/v1/hosts
```

## AD Modülü (Active Directory Keşif — Impacket)

Web arayüzünde **"🛡 AD Keşif"** sekmesinden veya API ile:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan/ad \
     -H "Content-Type: application/json" \
     -d '{"target": "10.0.0.5", "domain": "corp.local",
          "username": "alice", "password": "sifre",
          "tasks": ["dcinfo", "spn", "asrep"]}'
# -> {"job_id": "...", "ws_url": "/api/v1/ws/jobs/..."}   (aynı WebSocket akışı)

# Kritik CVE taraması (check-only, ayrı endpoint — görev her zaman ["cve"]):
curl -X POST http://127.0.0.1:8000/api/v1/ad/cve-scan \
     -H "Content-Type: application/json" \
     -d '{"target": "10.0.0.5", "domain": "corp.local",
          "username": "alice", "password": "sifre",
          "dc_hostname": "dc01.corp.local"}'
# -> {"job_id": "...", "ws_url": "/api/v1/ws/jobs/..."}

# Bulgu havuzu (tüm işlerin zafiyetleri, hash'ler dahil):
curl "http://127.0.0.1:8000/api/v1/ad/findings"
curl "http://127.0.0.1:8000/api/v1/ad/findings?job_id=..."
```

| Görev | Araç | Ne yapar |
|---|---|---|
| `dcinfo` | ldap3 | **DC envanteri (salt-okunur)**: DC makine hesabı `sAMAccountName`, `dNSHostName`, DN ve işletim sistemi bilgisini bulgulara ekler; AD'de değişiklik yapmaz |
| `spn` | GetUserSPNs | **Kerberoasting**: SPN'li hesaplar + TGS hash'leri |
| `asrep` | GetNPUsers | **AS-REP Roast**: pre-auth kapalı hesaplar + TGT hash'leri |
| `dcsync` | secretsdump | **DCSync**: NTDS NTLM hash dökümü (hassas — varsayılan dışı) |
| `acl` | bloodhound-python | **BloodHound ACL**: nesne/ACL toplama + `networkx` ile privesc yolu (`privesc_start` verilirse o hesaptan, boşsa en yakın saldırı adayı otomatik seçilir; zaten DOMAIN ADMINS üyesi hesaplar eleme ölçütüdür) |
| `cve` | CveScanner (impacket/ldap3) | **Kritik CVE tarayıcısı** — ZeroLogon (CVE-2020-1472, sıfır-anahtarlı Netlogon doğrulama denemesi; şifre ASLA değişmez), PrintNightmare (CVE-2021-34527, spoolss bind + yetkisiz `RpcOpenPrinter`; sürücü ekleme YOK), NoPac (CVE-2021-42278/42287, `requestPAC` karşılaştırmalı KDC davranışı + `ms-DS-MachineAccountQuota`; AD nesnesi oluşturulmaz) |

### 💥 SÖMÜR — Auto-Pwn (NoPac otomatik sömürü)

> ⚠️ **check-only DEĞİLDİR.** Bu modül ortamda **gerçek AD değişikliği** yapar:
> sahte makine hesabı oluşturur, sAMAccountName'i yeniden adlandırır ve
> **Domain Admin kimlikli bir Kerberos bileti (ccache) indirir.**
> Yalnızca **izinli** laboratuvarda, açıkça tanımladığınız hedeflere karşı kullanın.

Üç **katmanlı güvenlik kapısı** — hepsi açık olmalı, yoksa iş hiç başlamaz:

| # | Kapı | Nerede | Varsayılan |
|---|---|---|---|
| 1 | `EXPLOIT_ENABLED=true` | sunucu ortamı (`.env`) | **kapalı** |
| 2 | `EXPLOIT_ALLOWLIST` hedefi içermeli | sunucu ortamı (örn: `10.13.38.0/24,192.168.56.7`) | **boş** (her şey reddedilir) |
| 3 | `confirm: "SÖMÜR"` | API isteği + arayüzde çift onay (`confirm` + `SÖMÜR` yazma) | — |

Kapı 1+2 hem `/ad/exploit` endpoint'inde (403 → iş hiç başlamaz) hem de
`NopacExploiter.pwn()` içinde **yeniden doğrulanır** (savunma derinliği).
Allowlist'e alınmamış hiçbir hedefe tek bir paket bile gitmez.

**Zincir** (Ridter/noPac + Watchdogs Academy yarı-manuel akış):

```
1. addcomputer (SAMR)   → NM-XXXXXXXX$ sahte hesabı + rastgele 16 karakter şifre
2. LDAP                 → hesabın kendi SPN kayıtları temizlenir
3. LDAP                 → sAMAccountName = "dc01" (DC'nin $'suz adı)   [CVE-2021-42278]
4. getTGT               → bu adla TGT alınır (şifre bizde) → dc01.ccache
5. LDAP                 → sAMAccountName geri alınır (NM-XXXXXXXX$)
6. getST -impersonate   → TGT sunulur; KDC "dc01"i bulamaz, $ ekler ve GERÇEK
                          DC hesabını bulur → DA kimliğiyle cifs/DC bileti
                          [CVE-2021-42287] → Administrator@CIFS_….ccache
7. LDAP (best-effort)   → sahte hesap silinir (silinemezse logda uyarı)
```

```bash
# Sunucuyu sömürü kapılarıyla başlat (yalnızca lab!):
cd netmapper
EXPLOIT_ENABLED=true \
EXPLOIT_ALLOWLIST="10.13.38.0/24" \
python3 -m uvicorn app.main:app --reload

# Sömürü job'ı (confirm alanı zorunlu):
curl -X POST http://127.0.0.1:8000/api/v1/ad/exploit \
     -H "Content-Type: application/json" \
     -d '{"target": "10.13.38.5", "domain": "corp.local",
          "username": "alice", "password": "sifre",
          "confirm": "SÖMÜR", "da_user": "Administrator",
          "dc_hostname": "dc01.corp.local"}'
# -> {"job_id": "...", "ws_url": "...", "warning": "SAHTE HESAP OLUŞTURULDU…"}
```

- **Biletler:** `data/tickets/{job_id}/` altına (iş başına **izole** dizin)
  `0600` ile yazılır (dizin `0700`). Eşzamanlı işlerde dosya çakışması yoktur;
  eski işin biletleri yeni işin sonucu **sayılmaz**. Başarılı işte ara TGT
  temizlenir; başarısız işte dizin tamamen silinir. Saklama süresi
  `TICKETS_RETENTION_DAYS` (varsayılan 7 gün) — süresi dolanlar açılışta
  silinir. Başarı bulgusu yalnızca ccache **magic+boyut doğrulandıysa**
  `exploited` üretir.
- **Sonuç sınıflandırması** (bulgu `detail.outcome` alanı):
  `exploited` (DA bileti doğrulandı, critical) · `validated` (42278 kanıtlandı
  ama ST yok, high) · `attempted` (TGT'ye ulaşılamadı, medium) ·
  `inconclusive` (dosya var ama doğrulanamadı — kanıt sayılmaz, medium) ·
  `failed` (kapı engeli, info). Temizlik ayrı alan: `cleanup_status`
  (`ok/failed/unverified/skipped`) + `cleanup_failed` bayrağı + `manual_hint`;
  temizlik hatası ana işlem hatasını **maskelemez**. Silme, yeniden LDAP
  aramasıyla **doğrulanır** (çağrıldı ≠ doğrulandı).
- **Hedef tutarlılığı:** kapı hostname'i `getaddrinfo` ile çözer (IPv4+IPv6,
  çoklu cevap); **tüm** adresler allowlist içinde olmalı, belirsizlik
  reddedilir. Zincir LDAP/KDC bağlantılarında kapıdan dönen **doğrulanmış
  IP** kullanılır (hostname değil) → DNS rebinding/TOCTOU kapalı.
- **Temizlik:** varsayılan `EXPLOIT_CLEANUP=true` — zincir sonunda sahte hesap
  LDAP ile silinir **ve yeniden aranarak doğrulanır**; doğrulanamazsa job
  loglarında elle silme yönergesi (hesap adı + DN) görünür.
- **Şifreler:** hem operatör şifresi hem sahte hesap şifresi ProcessRunner
  `redact` ile maskelenir; loglara/JobState'e asla yazılmaz.
- Arayüzdeki **💥 SÖMÜR** butonu iki adımlı onay ister (özet dialog + `SÖMÜR`
  yazma); sunucu kapıları kapalıysa buton 403 mesajını gösterir.


- **Şifre güvenliği:** şifre yalnızca istek nesnesinde yaşar; `JobState`,
  DB ve loglara **asla yazılmaz** (ProcessRunner `redact` ile `***` maskeler,
  çıktılar da maskelenir). JSON dosyasına da yazılmaz.
- **Çıktılar:** bulgular hem ortak havuza (`ad_findings` tablosu →
  `/api/v1/ad/findings`) hem `data/raw/ad_findings_{job_id}.json` dosyasına
  yazılır (hash'ler dahil — pentest kanıtı).
- **Araç çözümü:** `impacket-*` (pip) → `*.py` (PATH) →
  `/usr/share/doc/python3-impacket/examples/` sırayla denenir; `.py` dosyaları
  shebang'den bağımsız `python3` ile koşulur. Kurulum: `pip install impacket`.
- Impacket hatalarda **exit 0** dönebilir; `[-] ...` hata imzaları ayrıca
  başarısızlık sayılır (ör. `Connection refused` → job `error`).
- ⚠️ Yalnızca **yetki verdiğiniz** domain ortamlarında kullanın.

## Mimari

```
netmapper/
├── app/
│   ├── main.py                    # FastAPI giriş noktası (lifespan -> init_db)
│   ├── config.py                  # Ayarlar (subnet, zaman aşımları, path'ler)
│   ├── core/
│   │   ├── process_runner.py      # asyncio subprocess wrapper (generic)
│   │   └── exceptions.py          # NetMapperError ağacı
│   ├── scanners/                  # ARAÇ-spesifik: netdiscover, nmap
│   ├── normalization/             # FORMAT-spesifik: XML/tablo -> ortak şema
│   ├── storage/                   # DB-spesifik: engine, tablolar, CRUD
│   ├── services/                  # BİRLEŞİM NOKTASI: orkestratör + job_manager
│   ├── reporting/                 # risk kuralları + PDF üretimi
│   └── api/                       # /scan, /jobs/{id}, /scans/{id}/report
├── data/raw/                      # Ham nmap XML çıktıları
├── data/reports/                  # Üretilen PDF'ler
├── tests/                         # Parser, risk ve API testleri
├── requirements.txt
└── README.md
```

### Veri akışı (tek yönlü, katmanlar birbirinden habersiz)

```
POST /scan ──> job_manager.start_scan()          (job_id hemen döner)
                  │ asyncio.create_task
                  ▼
           ScanOrchestrator.run_full_scan()
                  │  1) NetdiscoverScanner.scan(subnet)     → ham ARP tablosu
                  │     └─ netdiscover_parser.extract_ips() → ["192.168.1.10", ...]
                  │  2) NmapScanner.scan(ip) (eşzamanlı, semaphore) → ham XML dosyası
                  │     └─ nmap_parser.parse_nmap_xml()     → HostResult | None
                  │  2b) NiktoScanner — nmap ile AYNI anda (kör web portları)
                  │     └─ nikto_parser.parse_nikto_xml()   → web_findings (riski etkiler)
                  ▼
           list[HostResult]  (ortak Pydantic şeması)
                  │
                  ▼
           job_manager ──> repository.save_scan_results()   (SQLite: scan_jobs/hosts/services)
                  │        repository.set_job_status("done")
                  ▼
GET /jobs/{id}      → job_manager.get_job()   (hafıza → DB yedeği)
GET /scans/{id}/report
   → repository.get_hosts_with_services()
   → risk_rules.evaluate_host()               (kural tabanlı skor)
   → pdf_report.build_pdf_report()            (data/reports/report_{id}.pdf)
   → FileResponse (application/pdf)
```

### Mimari notlar

- **Modülerlik:** `scanners/` araç-spesifik, `normalization/`
  format-spesifik, `storage/` DB-spesifik — her biri birbirinden
  habersiz, `services/` katmanında birleşir. Yeni bir araç (örn.
  `arp-scan`) eklemek = yeni `scanners/arp_scan_scanner.py` +
  `normalization/arp_scan_parser.py` + orkestratöre iki satır.
- **Asenkron subprocess:** `asyncio.create_subprocess_exec` kullanılır;
  uzun taramalar FastAPI event loop'unu bloklamaz.
- **Job pattern:** `/scan` hemen `job_id` döner, durum `/jobs/{id}` ile
  sorgulanır. Anlık durum hafızada, kalıcı kayıt `scan_jobs` tablosunda
  (sunucu yeniden başlasa bile job + rapor sorgulanabilir).
- **Katmanlı storage:** `repository.py` tek CRUD kapısıdır; iş
  katmanı yalnızca fonksiyon imzalarını bilir.

## Testler

```bash
cd netmapper && python -m pytest -v
```

Testler subprocess çalıştırmaz (gerçek tarama yerine örnek XML/tablo
kullanır); `tests/conftest.py` test veritabanını geçici dizine alır.

## Yol haritası fikirleri

- `job_manager`'ı Redis'e taşımak (çoklu worker)
- `services/scan_orchestrator.py`'e servis-banner exploit kontrolü
- Web UI (tarama listesi + HTML rapor)
- Yetkilendirme: API anahtarı + tarama onay akışı
