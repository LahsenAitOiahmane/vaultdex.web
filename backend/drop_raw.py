import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from backend.config import get_settings

async def main():
    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL)
    async with engine.begin() as conn:
        print("Dropping all tables manually...")
        await conn.execute(text("DROP TABLE IF EXISTS scans CASCADE;"))
        await conn.execute(text("DROP TABLE IF EXISTS users CASCADE;"))
    print("Done dropping!")
    
    from backend.db.database import create_tables
    print("Recreating via ORM...")
    await create_tables()
    print("All done!")

if __name__ == "__main__":
    asyncio.run(main())
