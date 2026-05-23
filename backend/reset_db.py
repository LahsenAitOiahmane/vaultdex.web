import asyncio
from backend.db.database import drop_tables, create_tables
from backend.config import get_settings

async def main():
    print("Dropping tables...")
    await drop_tables()
    print("Creating tables...")
    await create_tables()
    print("Done!")

if __name__ == "__main__":
    asyncio.run(main())
