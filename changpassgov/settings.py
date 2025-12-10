# your_project/settings.py
import os
import sys

import environ
import ssl
from pathlib import Path
from django.contrib.messages import constants
from loguru import logger

BASE_DIR = Path(__file__).resolve().parent.parent

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),  # thư mục static của bạn
]
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
SETTINGS_DIR = Path(__file__).resolve().parent


DEBUG = False

if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
    ssl._create_default_https_context = ssl._create_unverified_context

env = environ.Env()

env_file = SETTINGS_DIR / (".env_prod" if not DEBUG else ".env_dev")
print(f"Using env file: {env_file}")
environ.Env.read_env(env_file)

SECRET_KEY = env("SECRET_KEY", default="w84i+2s^4kz1=n!f5_t=0cy8tgw_=*m3c0muv16kkj5h5j3v(z")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["*"])

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # For static files
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'changpassgov.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

ASGI_APPLICATION = 'changpassgov.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

REDIS_HOST = env("REDIS_HOST", default="localhost")
REDIS_PORT = env("REDIS_PORT", default="6379")
REDIS_PASSWORD = env("REDIS_PASSWORD", default="123456")
REDIS_USER = env("REDIS_USER", default=None)
REDIS_DBCACHE = env("REDIS_DBCACHE", default=5)


# Cache Configuration - Redis (Production)

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://default:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DBCACHE}",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT": 5,
            "COMPRESSOR": "django_redis.compressors.zlib.ZlibCompressor",
        },
    }
}



MESSAGE_TAGS = {
    constants.DEBUG: "secondary",
    constants.INFO: "info",
    constants.SUCCESS: "success",
    constants.WARNING: "warning",
    constants.ERROR: "danger",
}

#Config logging
DEBUG_LOG_PATH = f"{BASE_DIR}/logs/debug.log" if DEBUG else "/var/log/changpassgov/debug.log"
ERROR_LOG_PATH = f"{BASE_DIR}/logs/error.log" if DEBUG else "/var/log/changpassgov/error.log"

# Tạo thư mục logs
os.makedirs(os.path.dirname(ERROR_LOG_PATH), exist_ok=True)

# Xóa logger mặc định
logger.remove()

# 1. Console
console_level = "DEBUG" if DEBUG else "INFO"
logger.add(
    sys.stdout,
    level=console_level,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
    colorize=True,
)

# 2. File DEBUG - Chỉ trong development
if DEBUG:
    logger.add(
        DEBUG_LOG_PATH,
        rotation="50 MB",
        retention=2,  # Loguru tự động giữ 2 file mới nhất
        compression="zip",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module}:{function}:{line} | {message}",
        enqueue=True,
    )

# 3. File ERROR - Luôn bật
logger.add(
    ERROR_LOG_PATH,
    rotation="10 MB",
    retention=10,  # Loguru tự động giữ 10 file mới nhất
    compression="zip",
    level="ERROR",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module}:{function}:{line} | {message}",
    enqueue=True,
)

logger.info(f"Logging initialized - DEBUG mode: {DEBUG}")
# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Security Settings (Production)
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_HSTS_SECONDS = 31536000  # 1 năm
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


ZIMBRA_PREAUTH_KEY = "be8fd6a8d0076d4915f4adf9242d6282025aa2de6c9d6b735eb3d926b4c579f0"