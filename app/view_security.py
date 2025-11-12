import logging
import secrets

from django.core.cache import cache
from django.http import HttpResponseNotAllowed, JsonResponse
from django.template.response import TemplateResponse
from django.views.decorators.http import require_http_methods

from app.decorators import rate_limit
from app.forms import LoginForm
from app.utils import extract_domain, authenticate

logger = logging.getLogger(__name__)


@rate_limit(max_attempts=3, window=300, template_name="password_change/login.html", form_class=LoginForm)
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

            # 🔒 BƯỚC 2: Validate hostname format (prevent injection)
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
                rs = await authenticate(domain, email, password)
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
                    #Chỗ này có nên khóa account
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


@require_http_methods(["GET"])
async def redirect_intermediate_view(request, token):
    """
    🔒 Intermediate page: Lấy token từ cache và redirect đến Zimbra
    - Token chỉ dùng được 1 lần
    - Expire sau 60 giây
    - Validate IP nếu cần
    """
    cache_key = f"redirect_token:{token}"

    try:
        data = await cache.aget(cache_key)
    except Exception as e:
        logger.error(f"Cache get error: {str(e)}")
        data = None

    if not data:
        logger.warning(
            f"Invalid/expired redirect token: token={token}, "
            f"ip={request.META.get('REMOTE_ADDR', 'unknown')}"
        )
        return TemplateResponse(
            request,
            "password_change/redirect_error.html",
            {
                "message": "Link đã hết hạn hoặc không hợp lệ.",
                "detail": "Vui lòng đăng nhập lại."
            },
            status=400
        )

    # 🔒 Xóa token ngay (one-time use)
    try:
        await cache.adelete(cache_key)
    except Exception as e:
        logger.error(f"Cache delete error: {str(e)}")

    # 🔒 Optional: Kiểm tra IP khớp với lúc login
    current_ip = request.META.get('HTTP_X_FORWARDED_FOR')
    if current_ip:
        current_ip = current_ip.split(',')[0].strip()
    else:
        current_ip = request.META.get('REMOTE_ADDR', 'unknown')

    if data.get('ip') != current_ip:
        logger.warning(
            f"IP mismatch for redirect token: "
            f"login_ip={data.get('ip')}, redirect_ip={current_ip}, "
            f"email={data.get('email')}"
        )
        # Tuỳ chọn: có thể chặn hoặc cho phép
        # Ở đây tôi cho phép nhưng ghi log

    # 🔒 Construct final Zimbra URL
    zm_auth_token = data.get('zm_auth_token')
    hostname = data.get('hostname')
    domain = data.get('domain')

    zimbra_url = (
        f"https://{hostname}/login"
        f"?zm_auth_token={zm_auth_token}"
        f"&domain={domain}"
    )

    logger.info(
        f"Redirecting to Zimbra: email={data.get('email')}, "
        f"hostname={hostname}, ip={current_ip}"
    )

    # Generate CSP nonce for this page
    csp_nonce = secrets.token_urlsafe(16)

    # 🔒 Render intermediate page với auto-redirect
    response = TemplateResponse(
        request,
        "password_change/redirect_intermediate.html",
        {
            "zimbra_url": zimbra_url,
            "domain": domain,
            "hostname": hostname,
            "csp_nonce": csp_nonce
        }
    )

    # Set CSP header
    response['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{csp_nonce}'; "
        f"img-src 'self' data:; "
        f"connect-src 'self';"
    )

    return response