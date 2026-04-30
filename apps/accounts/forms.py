from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


class CambiarPasswordForm(forms.Form):
    password_actual = forms.CharField(
        label="Contraseña actual",
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Tu contraseña actual",
            "autocomplete": "current-password",
        }),
    )
    password_nueva = forms.CharField(
        label="Nueva contraseña",
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Mínimo 8 caracteres",
            "autocomplete": "new-password",
        }),
    )
    password_confirmar = forms.CharField(
        label="Confirmar nueva contraseña",
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Repite la nueva contraseña",
            "autocomplete": "new-password",
        }),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password_actual(self):
        password_actual = self.cleaned_data.get("password_actual")
        if not self.user.check_password(password_actual):
            raise ValidationError("La contraseña actual es incorrecta.")
        return password_actual

    def clean_password_nueva(self):
        password_nueva = self.cleaned_data.get("password_nueva")
        if password_nueva:
            validate_password(password_nueva, self.user)
        return password_nueva

    def clean(self):
        cleaned_data = super().clean()
        nueva = cleaned_data.get("password_nueva")
        confirmar = cleaned_data.get("password_confirmar")

        if nueva and confirmar and nueva != confirmar:
            self.add_error("password_confirmar", "Las contraseñas no coinciden.")

        return cleaned_data

    def save(self):
        """Aplica la nueva contraseña y guarda el usuario."""
        nueva = self.cleaned_data["password_nueva"]
        self.user.set_password(nueva)
        self.user.save()
        return self.user
