import asyncio
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'changpassgov.settings')
django.setup()

from app.utils import must_change_password,change_password_with_auth


async def main():
    x = await must_change_password(
        "interface.io.vn",
        "user05@interface.io.vn",
        "P@ssvv0rd567",
        "P@ssvv0rd11"
    )
    print(x)

if __name__ == "__main__":
    asyncio.run(main())