"""NetMapper uygulama ayarları. Ortam değişkenleriyle (ör. DATABASE_URL) ezilebilir."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "NetMapper"
    default_timeout_sec: int = 300
    netdiscover_timeout_sec: int = 90
    nmap_timeout_sec: int = 300
    nmap_binary: str = "nmap"
    netdiscover_binary: str = "netdiscover"
    raw_output_dir: str = "data/raw"
    report_output_dir: str = "data/reports"
    database_url: str = "sqlite+aiosqlite:///./netmapper.db"
    # Aynı anda taranacak maksimum host sayısı (nmap eşzamanlılığı)
    max_concurrent_scans: int = 5
    # Taranacak "kritik" portlar: HTTP/HTTPS, SSH, Telnet, SNMP, vb.
    critical_ports: str = (
        "21,22,23,25,53,80,110,143,161,443,445,554,993,995,1900,8080,8443"
    )
    # Nikto (web sunucusu taraması) — nmap ile AYNI anda başlatılır
    nikto_binary: str = "nikto"
    nikto_ports: str = "80,443,8080,8443"           # paralel "kör" tur portları
    nikto_maxtime_sec: int = 45                      # nikto -maxtime (hedef başına)
    nikto_timeout_sec: int = 360                     # süreç üst zaman aşımı
    # not: timeout > (port sayısı × maxtime + pay) olmalı; yoksa süreç
    # öldürülür ve yarım XML parse edilemez (bulgular kaybolur).

    # AD modülü (Impacket: GetUserSPNs / GetNPUsers / secretsdump)
    ad_timeout_sec: int = 300                        # görev başına süreç sınırı

    # ------------------------------------------------------------------
    # SÖMÜR (Auto-Pwn) modülü — NoPac (CVE-2021-42278 + CVE-2021-42287).
    # Bu modül GERÇEK AD DEĞİŞİKLİĞİ yapar (sahte makine hesabı oluşturur,
    # sAMAccountName'i yeniden adlandırır, Domain Admin biletini indirir).
    # Üç KATMANLI kapı; HEPESİ açık olmalı, yoksa sömürü çalışmaz:
    #   1) exploit_enabled=True            (sunucu anahtarı — varsayılan kapalı)
    #   2) hedef exploit_allowlist içinde   (yalnızca laboratuvar aralığı)
    #   3) istekte confirm="SÖMÜR"          (operatör onayı, API katmanı)
    # Kapılar hem routes (403) hem NopacExploiter.pwn (yeniden doğrulama) da.
    # ------------------------------------------------------------------
    exploit_enabled: bool = False                    # EXPLOIT_ENABLED=true
    exploit_allowlist: str = ""                      # "10.13.38.0/24,192.168.56.7"
    exploit_cleanup: bool = True                     # hesap silme denensin mi
    # confirm="SÖMÜR" onayı istensin mi (false = onaysız doğrudan sömürü)
    exploit_require_confirm: bool = True
    tickets_output_dir: str = "data/tickets"         # indirilen biletler (ccache)
    tickets_retention_days: int = 7                  # bilet saklama süresi (gün)

    # ------------------------------------------------------------------
    # API kimlik doğrulama (T2). TANIMLIYSA tüm /api/v1/* uçları token ister
    # (X-API-Token header / Bearer / WS ?token=). TANIMLI DEĞİLSE davranış
    # değişmez (localhost geliştirme) — uzak erişimde MUTLAKA ayarlayın.
    # ------------------------------------------------------------------
    api_token: str = ""                               # API_TOKEN (boş = kapalı)


settings = Settings()
