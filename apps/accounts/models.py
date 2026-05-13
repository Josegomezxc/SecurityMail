from django.db import models
from django.contrib.auth.models import User


# ═══════════════════════════════════════════════════════════════════════
#  USER PROFILE — extensión del User de Django para el avatar
# ═══════════════════════════════════════════════════════════════════════

def _avatar_upload_path(instance, filename):
    """
    Dónde se guardan las imágenes de perfil.
    Ej: media/avatars/12_perfil.jpg
    Guardamos por ID de usuario para evitar colisiones de nombres.
    """
    import os
    ext = os.path.splitext(filename)[1].lower() or '.jpg'
    return f"avatars/{instance.user_id}_avatar{ext}"


class UserProfile(models.Model):
    """
    Datos extra del usuario que no vienen en `django.contrib.auth.User`.
    Se crea automáticamente cuando se registra un usuario (ver signals.py).
    """
    user   = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile',
    )
    avatar = models.ImageField(
        upload_to=_avatar_upload_path, null=True, blank=True,
        help_text="Foto de perfil. Si está vacío se usa avatar por defecto (iniciales).",
    )
    # Si está True, los correos clasificados como SEGUROS (score 0-30) se reenvían
    # al correo real del usuario. Los sospechosos/maliciosos NUNCA se reenvían
    # (solo llegan las alertas de amenaza). Default: False (opt-in).
    forward_safe_emails = models.BooleanField(
        default=False,
        help_text="Reenviar correos seguros al correo real del usuario.",
    )
    # Sesión activa actual del usuario. Solo se permite una a la vez:
    # cuando alguien hace login, esta clave se actualiza con el nuevo
    # session_key y todas las sesiones anteriores quedan inválidas
    # (las controla SingleSessionMiddleware).
    current_session_key = models.CharField(
        max_length=40, blank=True, default='',
        help_text="Session key activa. Cualquier otra sesión del usuario será cerrada.",
    )
    # Último request del usuario en su sesión actual. Lo usamos para saber si
    # la sesión sigue "viva" (alguien la está usando) o ya quedó abandonada
    # (cerraron el navegador sin logout). El login bloquea si hay actividad
    # reciente en otra sesión.
    session_last_activity = models.DateTimeField(null=True, blank=True)
    # Si está True, el usuario demostró control sobre el correo ingresando
    # el código de 6 dígitos que enviamos a su buzón. Hasta que sea True,
    # la cuenta está deshabilitada (User.is_active = False).
    email_verified = models.BooleanField(default=False)
    # Ajuste de cupo de alias respecto al límite global ALIAS_LIMIT_PER_USER
    # (definido en apps/aliases/views.py). Puede ser POSITIVO (admin concedió
    # más alias al aprobar una solicitud) o NEGATIVO (admin redujo el cupo
    # manualmente desde el panel). El límite efectivo es:
    #     max(0, ALIAS_LIMIT_PER_USER + alias_quota_extra)
    alias_quota_extra = models.IntegerField(
        default=0,
        help_text="Ajuste de cupo de alias (positivo o negativo).",
    )
    # Si el admin marcó al usuario como "sin límite", puede crear alias sin
    # tope (igual que un staff, pero sin promoverlo a admin). El cupo
    # numérico (alias_quota_extra) deja de aplicar cuando este flag está
    # en True. Default: False — el usuario está sujeto al cupo normal.
    alias_unlimited = models.BooleanField(
        default=False,
        help_text="Concede al usuario alias ilimitados sin volverlo admin.",
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Perfil de {self.user.email or self.user.username}"

    @property
    def has_avatar(self) -> bool:
        return bool(self.avatar and self.avatar.name)

    @property
    def avatar_url(self) -> str:
        """URL del avatar si existe; cadena vacía si no (el template usa fallback)."""
        try:
            if self.avatar and self.avatar.name:
                return self.avatar.url
        except ValueError:
            pass
        return ''

    def delete_avatar_file(self):
        """Borra el archivo físico del disco si existe."""
        if self.avatar and self.avatar.name:
            try:
                self.avatar.delete(save=False)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════
#  TOKENS DE RECUPERACIÓN DE CONTRASEÑA
# ═══════════════════════════════════════════════════════════════════════

class PasswordResetToken(models.Model):
    """
    Token de un solo uso para restablecer la contraseña.
    Se genera cuando el usuario pide "Recuperar contraseña" y se envía por email.
    Expira a las 24h o cuando se usa (lo que pase antes).
    """
    user       = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='password_reset_tokens',
    )
    token      = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at    = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Token de recuperación'
        verbose_name_plural = 'Tokens de recuperación'

    @property
    def is_expired(self) -> bool:
        from django.utils import timezone
        return timezone.now() >= self.expires_at

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    @property
    def is_valid(self) -> bool:
        return not self.is_used and not self.is_expired

    def mark_used(self):
        from django.utils import timezone
        self.used_at = timezone.now()
        self.save(update_fields=['used_at'])

    def __str__(self):
        return f"Reset {self.token[:10]}… → {self.user.email}"


# ═══════════════════════════════════════════════════════════════════════
#  CÓDIGOS DE VERIFICACIÓN DE CORREO (registro)
# ═══════════════════════════════════════════════════════════════════════

class EmailVerificationCode(models.Model):
    """
    Código de 6 dígitos enviado al correo del usuario al registrarse,
    más un token único para identificar el flujo en la URL sin exponer
    el id del User.

    Flujo:
      1. Usuario se registra → creamos User con is_active=False y un
         EmailVerificationCode con código aleatorio.
      2. Enviamos correo con el código + redirigimos a /verificar-correo/<token>/
      3. Usuario pega el código → verificamos → marcamos email_verified=True,
         is_active=True y hacemos login automático.
    """
    user       = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='email_verification_codes',
    )
    code       = models.CharField(max_length=6, db_index=True)
    token      = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at    = models.DateTimeField(null=True, blank=True)
    attempts   = models.PositiveSmallIntegerField(
        default=0,
        help_text="Cuántas veces se intentó verificar este código (anti brute-force).",
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Código de verificación'
        verbose_name_plural = 'Códigos de verificación'

    @property
    def is_expired(self) -> bool:
        from django.utils import timezone
        return timezone.now() >= self.expires_at

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    @property
    def is_valid(self) -> bool:
        return not self.is_used and not self.is_expired and self.attempts < 5

    def mark_used(self):
        from django.utils import timezone
        self.used_at = timezone.now()
        self.save(update_fields=['used_at'])

    def __str__(self):
        return f"VerifyCode {self.code} → {self.user.email}"
