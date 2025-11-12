from django import forms

class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        max_length=254,
        widget=forms.EmailInput(attrs={
            "class": "form-control",
            "placeholder": "example@domain.com",
            "autocomplete": "email",
            "required": "required",
        })
    )
    password = forms.CharField(
        label="Mật khẩu",
        strip=False,
        min_length=8,
        max_length=128,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "••••••••",
            "autocomplete": "current-password",
            "required": "required",
        })
    )
