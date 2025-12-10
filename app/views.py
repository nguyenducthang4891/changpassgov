import re
from django.shortcuts import render
import secrets

from django.core.cache import cache
from django.http import HttpResponseNotAllowed, JsonResponse
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.views.decorators.http import require_http_methods
from django.contrib import messages

from app.decorators import rate_limit
from app.forms import LoginForm
from app.utils import extract_domain
from app.auth import change_password_with_auth_aiohttp, authenticate_aiohttp
from loguru import logger


@rate_limit(max_attempts=20, window=180, template_name="password_change/login.html", form_class=LoginForm)
async def login_view(request):
    """
    View xử lý đăng nhập
    - Validate domain whitelist
    - Authenticate với Zimbra
    - Tạo one-time redirect token
    - Trả về URL redirect an toàn
    """
    if request.method not in ("GET", "POST"):
        return HttpResponseNotAllowed(["GET", "POST"])

    form = LoginForm(request.POST or None)

    if request.method == "POST":
        # 🔒 Lấy IP để logging và security tracking
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR', 'unknown')

        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]
            domain = extract_domain(email)

            # 🔒 BƯỚC 1: Kiểm tra domain whitelist
            # if not domain or domain not in ALLOWED_DOMAINS:
            #     logger.warning(
            #         f"Unauthorized domain login attempt: domain={domain}, "
            #         f"email={email}, ip={ip_address}"
            #     )
            #     return JsonResponse({
            #         "success": False,
            #         "message": "Email hoặc mật khẩu không hợp lệ."
            #     }, status=401)

            hostname = f"mail.{domain}"
            if domain == 'mailpoc.cpt.gov.vn':
                hostname ='mailpoc.cpt.gov.vn'
            # 🔒 BƯỚC 2: Validhostnameate hostname format (prevent injection)
            if not hostname.replace('.', '').replace('-', '').isalnum():
                logger.error(
                    f"Invalid hostname format: hostname={hostname}, "
                    f"email={email}, ip={ip_address}"
                )
                return JsonResponse({
                    "success": False,
                    "message": "Có lỗi xảy ra. Vui lòng thử lại."
                }, status=400)

            # 🔒 BƯỚC 3: Authenticate với Zimbra
            try:
                rs = await authenticate_aiohttp(domain, email, password)
            except Exception as e:
                logger.error(
                    f"Zimbra authentication error: email={email}, "
                    f"ip={ip_address}, error={str(e)}"
                )
                return JsonResponse({
                    "success": False,
                    "message": "Không thể kết nối đến máy chủ. Vui lòng thử lại sau."
                }, status=503)

            if rs and rs.get("success"):
                zm_auth_token = rs.get("authToken")
                if not zm_auth_token:
                    logger.error(f"No authToken in response for {email}")
                    return JsonResponse({
                        "success": False,
                        "message": "Có lỗi xảy ra. Vui lòng thử lại."
                    }, status=500)
                mustChangePassword = rs.get("mustChangePassword", False)

                if mustChangePassword:
                    messages.warning(request, f"Bạn đăng nhập lần đầu, vui lòng thay đổi mật khẩu")
                    return JsonResponse({
                        "success": True,
                        "message": "Vui lòng thay đổi mật khẩu",
                        "redirect_url": f"/change-password/?email={email}"
                    }, status=401)
                # 🔒 BƯỚC 4: Tạo one-time redirect token
                redirect_token = secrets.token_urlsafe(32)
                cache_key = f"redirect_token:{redirect_token}"

                # Lưu token với TTL ngắn (60 giây)
                cache_data = {
                    "zm_auth_token": zm_auth_token,
                    "domain": domain,
                    "hostname": hostname,
                    "email": email,
                    "ip": ip_address,
                    "created_at": __import__('time').time()
                }

                try:
                    await cache.aset(cache_key, cache_data, timeout=60)
                except Exception as e:
                    logger.error(f"Cache error: {str(e)}")
                    return JsonResponse({
                        "success": False,
                        "message": "Có lỗi xảy ra. Vui lòng thử lại."
                    }, status=500)

                logger.info(
                    f"Successful login: email={email}, ip={ip_address}, "
                    f"redirect_to={hostname}"
                )

                # 🔒 BƯỚC 5: Trả về URL đến intermediate page
                # KHÔNG trả zm_auth_token trong response này

                return JsonResponse({
                    "success": True,
                    "redirect_url": f"/auth/redirect/{redirect_token}"
                })

            # 🔒 Login failed - log và đếm số lần fail
            logger.warning(
                f"Failed login attempt: email={email}, ip={ip_address}"
            )

            # Đếm số lần fail để có thể implement account lockout
            fail_key = f"login_fail:{email}"
            try:
                fail_count = await cache.aget(fail_key, default=0)
                fail_count = int(fail_count) + 1
                await cache.aset(fail_key, fail_count, timeout=3600)

                if fail_count >= 5:
                    # Chỗ này có nên khóa account
                    logger.error(
                        f"Possible brute force attack: email={email}, "
                        f"failures={fail_count}, ip={ip_address}"
                    )
            except Exception as e:
                logger.error(f"Failed to track login failures: {str(e)}")

            return JsonResponse({
                "success": False,
                "message": "Email hoặc mật khẩu không hợp lệ."
            }, status=401)
        else:
            # Form validation errors
            errors = {field: error[0] for field, error in form.errors.items()}
            return JsonResponse({
                "success": False,
                "errors": errors
            }, status=400)

    # GET request → render template với CSP nonce
    csp_nonce = secrets.token_urlsafe(16)
    response = TemplateResponse(
        request,
        "password_change/login.html",
        {
            "form": form,
            "csp_nonce": csp_nonce
        }
    )

    # 🔒 Set CSP header với nonce
    response['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        f"script-src 'self' 'nonce-{csp_nonce}' https://cdn.jsdelivr.net; "
        f"font-src 'self' https://cdn.jsdelivr.net; "
        f"img-src 'self' data:; "
        f"connect-src 'self';"
    )

    return response


# app/views.py

@require_http_methods(["GET"])
async def redirect_intermediate_view(request, token):
    """
    Intermediate page: Lấy token từ cache và redirect đến Zimbra
    """
    cache_key = f"redirect_token:{token}"

    try:
        data = await cache.aget(cache_key)
    except Exception as e:
        logger.error(f"Cache get error: {str(e)}")
        data = None

    if not data:
        logger.warning(f"Invalid/expired redirect token: token={token}")
        return TemplateResponse(
            request,
            "password_change/redirect_error.html",
            {"message": "Link đã hết hạn hoặc không hợp lệ."},
            status=400
        )

    # Xóa token (one-time use)
    try:
        await cache.adelete(cache_key)
    except Exception as e:
        logger.error(f"Cache delete error: {str(e)}")

    zm_auth_token = data.get('zm_auth_token')
    hostname = data.get('hostname')
    domain = data.get('domain')

    # ⚠️ FIX: Construct URL với encoded token
    from urllib.parse import quote

    zimbra_url = (
        f"https://{hostname}/login"
        f"?zm_auth_token={quote(zm_auth_token)}"
        f"&domain={quote(domain)}"
    )

    logger.info(f"Redirecting to Zimbra: email={data.get('email')}, hostname={hostname}")

    csp_nonce = secrets.token_urlsafe(16)

    response = TemplateResponse(
        request,
        "password_change/redirect_intermediate.html",
        {
            "zimbra_url": zimbra_url,
            "domain": domain,
            "hostname": hostname,
            "csp_nonce": csp_nonce,
            # ⚠️ ADD: Pass user agent info
            "is_mobile": is_mobile_browser(request),
        }
    )

    # ⚠️ FIX: Relaxed CSP for mobile
    response['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{csp_nonce}'; "
        f"img-src 'self' data:; "
        f"connect-src 'self' https://{hostname};"  # Allow connect to Zimbra
    )

    # ⚠️ FIX: Add headers to prevent caching
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'

    return response


def is_mobile_browser(request):
    """Detect mobile browser"""
    user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
    mobile_keywords = ['android', 'iphone', 'ipad', 'mobile', 'webos']
    return any(keyword in user_agent for keyword in mobile_keywords)


@rate_limit(max_attempts=20, window=180, template_name="password_change/change_password.html", form_class=None)
async def change_password(request):
    """
    View để hiển thị form và xử lý đổi mật khẩu
    """
    if request.method == 'GET':
        email = request.GET.get("email","")
        return render(request, 'password_change/change_password.html', {'email': email})

    # POST request
    email = request.POST.get('email', '').strip()
    old_password = request.POST.get('old_password', '')
    new_password = request.POST.get('new_password', '')
    confirm_password = request.POST.get('confirm_password', '')

    # Validation
    if not all([email, old_password, new_password, confirm_password]):
        messages.error(request, 'Vui lòng điền đầy đủ thông tin')
        return render(request, 'password_change/change_password.html')

    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        messages.error(request, 'Định dạng email không hợp lệ')
        return render(request, 'password_change/change_password.html')

    # Validate password match
    if new_password != confirm_password:
        messages.error(request, 'Mật khẩu mới không khớp')
        return render(request, 'password_change/change_password.html')

    # Validate password strength
    if len(new_password) < 8:
        messages.error(request, 'Mật khẩu mới phải có ít nhất 8 ký tự')
        return render(request, 'password_change/change_password.html')

    if not re.search(r'[A-Z]', new_password):
        messages.error(request, 'Mật khẩu phải có ít nhất 1 chữ hoa')
        return render(request, 'password_change/change_password.html')

    if not re.search(r'[a-z]', new_password):
        messages.error(request, 'Mật khẩu phải có ít nhất 1 chữ thường')
        return render(request, 'password_change/change_password.html')

    if not re.search(r'[0-9]', new_password):
        messages.error(request, 'Mật khẩu phải có ít nhất 1 chữ số')
        return render(request, 'password_change/change_password.html')

    # Extract domain
    domain = extract_domain(email)

    if not domain:
        messages.error(request, 'Không thể trích xuất domain từ email')
        return render(request, 'password_change/change_password.html')

    # Call SOAP API
    result = await change_password_with_auth_aiohttp(domain, email, old_password, new_password)

    if result['success']:
        messages.success(request, result['message'])
        return render(request, 'password_change/success.html', {'email': email})
    else:
        messages.error(request, f'Lỗi: {result["error"]}')
        return render(request, 'password_change/change_password.html', {'email': email})
