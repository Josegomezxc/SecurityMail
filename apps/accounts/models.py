from django.db import models
from django.contrib.auth.models import User


def _avatar_upload_path(instance, filename):
    import os
    ext = os.path.splitext(filename)[1].lower() or '.jpg'
    return f"avatars/{instance.user_id}_avatar{ext}"


class UserProfile(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_perfil_usuario')
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile', db_column='id_usuario',
    )
    avatar = models.ImageField(
        upload_to=_avatar_upload_path, null=True, blank=True,
        db_column='avatar',
        help_text="Foto de perfil. Si está vacío se usa avatar por defecto (iniciales).",
    )
    forward_safe_emails = models.BooleanField(
        default=False, db_column='reenviar_correos_seguros',
        help_text="Reenviar correos seguros al correo real del usuario.",
    )
    email_verified = models.BooleanField(
        default=False, db_column='correo_verificado',
    )
    alias_quota_extra = models.IntegerField(
        default=0, db_column='cupo_alias_extra',
        help_text="Ajuste de cupo de alias (positivo o negativo).",
    )
    alias_unlimited = models.BooleanField(
        default=False, db_column='alias_ilimitados',
        help_text="Concede al usuario alias ilimitados sin volverlo admin.",
    )
    last_toast_notif_id = models.PositiveBigIntegerField(
        default=0, db_column='ultimo_toast_id',
        help_text="ID máximo de notificación cuyo toast ya se mostró.",
    )
    is_deleted = models.BooleanField(
        default=False, db_column='eliminado',
        help_text="Soft delete: marca la cuenta como eliminada sin borrar los datos.",
    )
    deleted_at = models.DateTimeField(
        null=True, blank=True, db_column='eliminado_en',
        help_text="Cuándo se marcó la cuenta como eliminada.",
    )
    deletion_ip = models.GenericIPAddressField(
        null=True, blank=True, db_column='ip_eliminacion',
        help_text="IP desde donde se solicitó la eliminación.",
    )
    updated_at = models.DateTimeField(auto_now=True, db_column='actualizado_en')
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_perfil_usuario'

    def __str__(self):
        return f"Perfil de {self.user.email or self.user.username}"

    @property
    def has_avatar(self) -> bool:
        return bool(self.avatar and self.avatar.name)

    @property
    def avatar_url(self) -> str:
        try:
            if self.avatar and self.avatar.name:
                return self.avatar.url
        except ValueError:
            pass
        return ''

    def delete_avatar_file(self):
        if self.avatar and self.avatar.name:
            try:
                self.avatar.delete(save=False)
            except Exception:
                pass


class UserSession(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_sesion_usuario')
    profile = models.OneToOneField(
        UserProfile, on_delete=models.CASCADE, related_name='session',
        db_column='id_perfil_usuario',
    )
    current_session_key = models.CharField(
        max_length=40, blank=True, default='', db_column='sesion_actual',
        help_text="Session key activa. Cualquier otra sesión del usuario será cerrada.",
    )
    session_last_activity = models.DateTimeField(
        null=True, blank=True, db_column='ultima_actividad_sesion',
    )
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_sesion_usuario'


class AccountLock(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_bloqueo_cuenta')
    profile = models.OneToOneField(
        UserProfile, on_delete=models.CASCADE, related_name='lock',
        db_column='id_perfil_usuario',
    )
    failed_login_attempts = models.PositiveIntegerField(
        default=0, db_column='intentos_fallidos',
        help_text="Intentos consecutivos de password incorrecta. Se resetea al login exitoso.",
    )
    temp_locked_until = models.DateTimeField(
        null=True, blank=True, db_column='bloqueo_temp_hasta',
        help_text="Si > now, la cuenta está bloqueada temporalmente.",
    )
    temp_lock_triggered = models.BooleanField(
        default=False, db_column='bloqueo_temp_activado',
        help_text="True una vez que se disparó el temp lock. La siguiente falla = bloqueo permanente.",
    )
    permanent_lock_reason = models.TextField(
        blank=True, default='', db_column='motivo_bloqueo_perm',
        help_text="Motivos que se muestran al usuario en la card de cuenta bloqueada.",
    )
    permanent_lock_at = models.DateTimeField(
        null=True, blank=True, db_column='bloqueo_perm_en',
        help_text="Cuándo se bloqueó permanentemente la cuenta por intentos fallidos.",
    )
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_bloqueo_cuenta'


class PasswordResetToken(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_token_recuperacion')
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='password_reset_tokens',
        db_column='id_usuario',
    )
    token = models.CharField(max_length=64, unique=True, db_index=True, db_column='token')
    created_at = models.DateTimeField(auto_now_add=True, db_column='creado_en')
    expires_at = models.DateTimeField(db_column='expira_en')
    used_at = models.DateTimeField(null=True, blank=True, db_column='usado_en')
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_column='direccion_ip')
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_token_recuperacion'
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


class EmailVerificationCode(models.Model):
    PURPOSE_CHOICES = [
        ('register',       'Verificación de registro'),
        ('delete_account', 'Confirmar eliminación de cuenta'),
    ]

    id = models.AutoField(primary_key=True, db_column='id_codigo_verificacion')
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='email_verification_codes',
        db_column='id_usuario',
    )
    purpose = models.CharField(
        max_length=20, choices=PURPOSE_CHOICES, default='register', db_index=True,
        db_column='proposito',
        help_text='Para qué acción se usa este código.',
    )
    code = models.CharField(max_length=6, db_index=True, db_column='codigo')
    token = models.CharField(max_length=64, unique=True, db_index=True, db_column='token')
    created_at = models.DateTimeField(auto_now_add=True, db_column='creado_en')
    expires_at = models.DateTimeField(db_column='expira_en')
    used_at = models.DateTimeField(null=True, blank=True, db_column='usado_en')
    attempts = models.PositiveSmallIntegerField(
        default=0, db_column='intentos',
        help_text="Cuántas veces se intentó verificar este código (anti brute-force).",
    )
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_codigo_verificacion'
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


class PendingRegistration(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_registro_pendiente')
    email = models.EmailField(db_index=True, db_column='correo')
    first_name = models.CharField(max_length=150, db_column='nombre')
    password_hash = models.CharField(
        max_length=128, db_column='hash_contrasena',
        help_text="Contraseña hasheada con django.contrib.auth.hashers.make_password.",
    )
    code = models.CharField(max_length=6, db_index=True, db_column='codigo')
    token = models.CharField(max_length=64, unique=True, db_index=True, db_column='token')
    created_at = models.DateTimeField(auto_now_add=True, db_column='creado_en')
    expires_at = models.DateTimeField(db_column='expira_en')
    used_at = models.DateTimeField(null=True, blank=True, db_column='usado_en')
    attempts = models.PositiveSmallIntegerField(
        default=0, db_column='intentos',
        help_text="Cuántas veces se intentó verificar (anti brute-force).",
    )
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_registro_pendiente'
        ordering = ['-created_at']
        verbose_name = 'Registro pendiente'
        verbose_name_plural = 'Registros pendientes'

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
        return f"PendingRegistration {self.email} (code={self.code})"


class AccountRecoveryRequest(models.Model):
    STATUS = [
        ('pending',  'Pendiente'),
        ('approved', 'Aprobada'),
        ('rejected', 'Rechazada'),
    ]

    id = models.AutoField(primary_key=True, db_column='id_solicitud_recuperacion')
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='account_recovery_requests',
        db_column='id_usuario',
    )
    reason = models.TextField(
        db_column='motivo',
        help_text="Explicación del usuario de por qué quiere recuperar la cuenta.",
    )
    status = models.CharField(
        max_length=10, choices=STATUS, default='pending', db_column='estado',
    )
    admin_note = models.TextField(
        blank=True, db_column='nota_admin',
        help_text="Nota del admin al aprobar/rechazar (opcional).",
    )
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='resolved_account_recovery_requests', db_column='id_resuelto_por',
    )
    created_at = models.DateTimeField(auto_now_add=True, db_column='creado_en')
    resolved_at = models.DateTimeField(null=True, blank=True, db_column='resuelto_en')
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_solicitud_recuperacion'
        ordering = ['-created_at']
        verbose_name = 'Solicitud de recuperación de cuenta'
        verbose_name_plural = 'Solicitudes de recuperación de cuenta'
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self):
        return f"Recovery {self.user.email} ({self.status})"
