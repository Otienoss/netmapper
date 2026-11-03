"""SQLModel async engine ve oturum fabrikası."""

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings

engine = create_async_engine(settings.database_url, echo=False)

# SQLModel'in AsyncSession'ı SQLAlchemy'in türevidir + .exec() sorgu kolaylaştırıcısı
# getirir; repository katmanı session.exec(...) kullanır.
async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def init_db() -> None:
    """Uygulama başlarken tabloları oluşturur (ilk çalıştırmada migration gerekmez)."""
    from app.storage import models  # noqa: F401  # tabloların metadata'ya kaydı için

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

        # Hafif şema migration'ı: eski DB'lerde eksik kolonları ekle
        def _ensure_columns(sync_conn):
            existing: set[str] = set()
            rows = sync_conn.exec_driver_sql(
                "PRAGMA table_info(scan_jobs)"
            ).fetchall()
            existing = {r[1] for r in rows}
            for col, ddl in (
                ("profile", "VARCHAR NOT NULL DEFAULT 'full'"),
                ("module", "VARCHAR NOT NULL DEFAULT 'net'"),
            ):
                if existing and col not in existing:
                    sync_conn.exec_driver_sql(
                        f"ALTER TABLE scan_jobs ADD COLUMN {col} {ddl}"
                    )

        await conn.run_sync(_ensure_columns)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI bağımlılığı: request başına tek oturum."""
    async with async_session_factory() as session:
        yield session
