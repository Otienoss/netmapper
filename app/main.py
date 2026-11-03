import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as scan_router
from app.api.arp_routes import router as arp_router
from app.config import settings
from app.core.auth import is_authorized
from app.scanners.nopac_exploiter import purge_expired_tickets
from app.storage.database import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"
_INDEX_HTML = _STATIC_DIR / "index.html"


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Başlangıçta DB tablolarını oluşturur + süresi dolan biletleri temizler."""
    await init_db()
    purged = purge_expired_tickets()
    if purged:
        logger.info("Ticket retention: %d eski bilet girdisi silindi", purged)
    if settings.api_token:
        logger.info("API_TOKEN tanımlı — /api/v1 kimlik doğrulama ETKİN")
    else:
        logger.warning(
            "API_TOKEN tanımlı DEĞİL — API kimlik doğrulaması KAPALI "
            "(yalnızca localhost dağıtımı için; uzak erişimde API_TOKEN ayarlayın)"
        )
    if settings.exploit_enabled:
        logger.warning(
            "SÖMÜR modülü AÇIK — allowlist: %s (yalnızca izinli laboratuvar; "
            "istekte confirm=\"SÖMÜR\" yine zorunlu)",
            settings.exploit_allowlist or "BOŞ (tüm hedefler reddedilir)",
        )
    else:
        logger.info("SÖMÜR modülü kapalı (EXPLOIT_ENABLED tanımlı değil)")
    yield


app = FastAPI(title="NetMapper", version="0.1.0", lifespan=lifespan)
app.include_router(scan_router, prefix="/api/v1")
app.include_router(arp_router, prefix="/api/v1")


@app.middleware("http")
async def _api_token_middleware(request: Request, call_next):
    """Tüm /api/v1/* için token denetimi (route bağımsız savunma katmanı)."""
    path = request.url.path
    if path.startswith("/api/v1") and not is_authorized(request):
        return JSONResponse(
            status_code=401,
            content={
                "detail": (
                    "Yetkisiz: API_TOKEN tanımlı — 'X-API-Token' header'ı veya "
                    "'Authorization: Bearer <token>' gerekli."
                )
            },
        )
    return await call_next(request)

# Paneller (NetMapper Dashboard tasarımı): /static/panels/*.html
app.mount(
    "/static",
    StaticFiles(directory=_STATIC_DIR, html=True),
    name="static",
)


@app.get("/", include_in_schema=False)
async def index():
    """Kabuk sayfa: Dashboard / Yeni Tarama / Host Envanteri panelleri."""
    return FileResponse(_INDEX_HTML, media_type="text/html")


@app.get("/health")
async def health():
    return {"status": "ok"}
