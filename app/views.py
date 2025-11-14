import re
from django.shortcuts import render
from django.contrib import messages

from app.decorators import rate_limit
from app.utils import extract_domain, change_password_with_auth


@rate_limit(max_attempts=5, window=180, template_name="password_change/change_password.html", form_class=None)
async def change_password(request):
    """
    View để hiển thị form và xử lý đổi mật khẩu
    """
    if request.method == 'GET':
        email = request.GET.get("email")
        return render(request, 'password_change/change_password.html',{'email':email})

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
    result = await change_password_with_auth(domain, email, old_password, new_password)

    if result['success']:
        messages.success(request, result['message'])
        redirect_url = f"https://mail.{domain}"
        return render(request, 'password_change/success.html', {'email': email, 'redirect_url': redirect_url})
    else:
        messages.error(request, f'Lỗi: {result["error"]}')
        return render(request, 'password_change/change_password.html')

