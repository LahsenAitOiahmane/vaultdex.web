import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from backend.config import get_settings

async def main():
    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL)
    async with engine.begin() as conn:
        print("Truncating all tables...")
        await conn.execute(text("TRUNCATE TABLE scans CASCADE;"))
        await conn.execute(text("TRUNCATE TABLE users CASCADE;"))
    print("Database cleaned completely!")

if __name__ == "__main__":
    asyncio.run(main())
