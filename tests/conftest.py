"""Test sabiti: import'lardan ÖNCE test veritabanı ayarlanır.

app.config modül seviyesinde Settings() ürettiği için ortam değişkeni
ilk importtan önce tanımlanmalıdır.

Ayrıca testler geliştiricinin yerel .env'inden BAĞIMSIZ olsun diye
sömürü kapıları ve API token'ı burada kapatılır (pydantic-settings
önceliği: ortam değişkeni > .env). Aksi halde .env'de EXPLOIT_ENABLED=true
varsa varsayılan-kapalı testleri geliştirici makinesine göre yanıltır.
"""

import os
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="netmapper-test-")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmpdir}/test_netmapper.db"

# Sömürü kapıları + auth test ortamında deterministik olsun (fail-closed).
os.environ["EXPLOIT_ENABLED"] = "false"
os.environ["EXPLOIT_ALLOWLIST"] = ""
os.environ["EXPLOIT_REQUIRE_CONFIRM"] = "true"
os.environ["API_TOKEN"] = ""
