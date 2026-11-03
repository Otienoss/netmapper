"""API kimlik doğrulama (T2) — statik API token'ı.

Model: tek-operatörlü dağıtım (bu aracın mimarisi çok kiracılı DEĞİL).
  - API_TOKEN ortam değişkeni tanımlıysa TÜM /api/v1/* uçları token ister:
      header:  X-API-Token: <token>   veya   Authorization: Bearer <token>
      WebSocket: ?token=<token> sorgu parametresi (tarayıcılar WS'te header
      set edemez)
  - Token karşılaştırması secrets.compare_digest ile timing-safe.
  - API_TOKEN TANIMLI DEĞİLSE davranış değişmez (geriye uyumluluk) — ancak
    sunucu açılışında güvenlik uyarısı basılır. Üretim/uzak erişimde token
    ZORUNLUDUR; UI token.js ile 401'de token ister.
  - /health ve statik dosyalar auth dışındadır (liveness + kabuk sayfası).
"""

import secrets

from fastapi import HTTPException, Request, WebSocket

from app.config import settings

_EXEMPT_PREFIXES = ("/health", "/static", "/docs", "/openapi.json", "/redoc")


def _extract_token(request: Request) -> str | None:
    """Header'dan (veya WS için sorgudan) token'ı çıkarır."""
    token = request.headers.get("x-api-token")
    if token:
        return token.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _matches(token: str | None) -> bool:
    """Token'ı ayarla timing-safe karşılaştırır (None → asla eşleşmez)."""
    expected = settings.api_token
    if not expected or not token:
        return False
    return secrets.compare_digest(token, expected)


def is_authorized(request: Request) -> bool:
    """HTTP isteği yetkili mi? (token tanımlı değilse True — kapalı mod.)"""
    if not settings.api_token:
        return True
    return _matches(_extract_token(request))


def require_api_token(request: Request) -> None:
    """FastAPI dependency: yetkisizse 401 döndürür."""
    if request.url.path in _EXEMPT_PREFIXES or any(
        request.url.path.startswith(p) for p in ("/static", "/docs", "/redoc")
    ):
        return
    if not settings.api_token:
        return
    if not is_authorized(request):
        raise HTTPException(
            status_code=401,
            detail=(
                "Yetkisiz: API_TOKEN tanımlı — 'X-API-Token' header'ı veya "
                "'Authorization: Bearer <token>' gerekli."
            ),
        )


def is_websocket_authorized(websocket: WebSocket) -> bool:
    """WS bağlantısı yetkili mi? (?token= sorgu parametresi okunur.)"""
    if not settings.api_token:
        return True
    return _matches(websocket.query_params.get("token"))