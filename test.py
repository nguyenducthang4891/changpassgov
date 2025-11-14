import asyncio
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'changpassgov.settings')
django.setup()

from app.auth import change_password_with_auth_aiohttp

async def main():
    x = await change_password_with_auth_aiohttp(
        "interface.io.vn",
        "user05@interface.io.vn",
        "P@ssvv0rd567",
        "P@ssvv0rd11"
    )
    print(x)

if __name__ == "__main__":
    asyncio.run(main())