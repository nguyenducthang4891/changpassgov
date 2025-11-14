import os
import re
import asyncio
import ssl
import httpx
import logging
from loguru import logger


def get_client_ip(request):
    """Lấy IP của client"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def extract_domain(email):
    """Trích xuất domain từ email"""
    match = re.match(r'^[^@]+@(.+)$', email)
    if match:
        return match.group(1)
    return None



