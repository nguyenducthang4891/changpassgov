from django.core.cache import cache
from django.contrib import messages
from django.template.response import TemplateResponse
from functools import wraps
import hashlib

from app.utils import get_client_ip


def rate_limit(max_attempts=5, window=300, template_name=None, form_class=None):
    """
    Decorator giới hạn số lần thử POST (theo email & IP)
    - template_name: template fallback khi bị giới hạn
    - form_class: form để render lại nếu bị chặn (tùy từng view)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(request, *args, **kwargs):
            if request.method == "POST":
                email = request.POST.get("email", "").strip().lower()
                ip = get_client_ip(request)

                email_key = f"rate_limit_email_{hashlib.md5(email.encode()).hexdigest()}"
                ip_key = f"rate_limit_ip_{ip.replace('.', '_')}"

                email_attempts = cache.get(email_key, 0)
                ip_attempts = cache.get(ip_key, 0)
                ttl_func = getattr(cache, "ttl", lambda k: window)

                # Quá giới hạn email
                if email_attempts >= max_attempts:
                    remaining_time = ttl_func(email_key)
                    messages.error(
                        request,
                        f"Bạn đã thử quá nhiều lần với email này. "
                        f"Vui lòng thử lại sau {remaining_time // 60} phút."
                    )
                    ctx = {"form": form_class()} if form_class else {}
                    return TemplateResponse(request, template_name or "error.html", ctx)

                # Quá giới hạn IP
                if ip_attempts >= max_attempts * 2:
                    remaining_time = ttl_func(ip_key)
                    messages.error(
                        request,
                        f"Quá nhiều yêu cầu từ IP của bạn. "
                        f"Vui lòng thử lại sau {remaining_time // 60} phút."
                    )
                    ctx = {"form": form_class()} if form_class else {}
                    return TemplateResponse(request, template_name or "error.html", ctx)

                # Tăng bộ đếm
                cache.set(email_key, email_attempts + 1, window)
                cache.set(ip_key, ip_attempts + 1, window)

            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
