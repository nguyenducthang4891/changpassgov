from functools import wraps
import hashlib

from django.contrib import messages
from django.core.cache import cache

from django.http import HttpResponseForbidden
from django.shortcuts import render

from app.utils import get_client_ip


def rate_limit(max_attempts=5, window=300):  # 5 lần trong 5 phút
    """
    Decorator để rate limit theo email và IP
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(request, *args, **kwargs):
            if request.method == 'POST':
                email = request.POST.get('email', '').strip().lower()
                ip = get_client_ip(request)

                # Tạo keys cho cache
                email_key = f"rate_limit_email_{hashlib.md5(email.encode()).hexdigest()}"
                ip_key = f"rate_limit_ip_{ip.replace('.', '_')}"

                # Kiểm tra rate limit cho email
                email_attempts = cache.get(email_key, 0)
                if email_attempts >= max_attempts:
                    remaining_time = cache.ttl(email_key)
                    messages.error(request,
                                   f'Bạn đã thử quá nhiều lần với email này. '
                                   f'Vui lòng thử lại sau {remaining_time // 60} phút.')
                    return render(request, 'password_change/change_password.html')

                # Kiểm tra rate limit cho IP
                ip_attempts = cache.get(ip_key, 0)
                if ip_attempts >= max_attempts * 2:  # IP có limit cao hơn
                    remaining_time = cache.ttl(ip_key)
                    messages.error(request,
                                   f'Quá nhiều yêu cầu từ IP của bạn. '
                                   f'Vui lòng thử lại sau {remaining_time // 60} phút.')
                    return render(request, 'password_change/change_password.html')

                # Tăng counter
                cache.set(email_key, email_attempts + 1, window)
                cache.set(ip_key, ip_attempts + 1, window)

            return await func(request, *args, **kwargs)

        return wrapper

    return decorator