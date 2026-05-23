import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from backend.config import get_settings

async def main():
    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL)
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'scans';
        """))
        columns = result.fetchall()
        print("Columns in 'scans' table:")
        for col in columns:
            print(f" - {col[0]}: {col[1]}")
            
if __name__ == "__main__":
    asyncio.run(main())
