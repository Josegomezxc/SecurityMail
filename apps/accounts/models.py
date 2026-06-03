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
    # ID de la notificación más reciente cuyo TOAST ya se mostró al usuario.
    # Se actualiza server-side cada vez que el dropdown del bell muestra
    # toasts, así otros dispositivos del mismo usuario NO vuelven a verlos.
    # Antes esto vivía en localStorage del navegador → era per-dispositivo,
    # rompía la sincronía cuando el usuario abría su cuenta en celular + PC.
    last_toast_notif_id = models.PositiveBigIntegerField(
        default=0,
        help_text="ID máximo de notificación cuyo toast ya se mostró.",
    )
    # ── Soft delete (borrado lógico) ──────────────────────────────────
    # En lugar de borrar físicamente el User (que arrastra alias, correos,
    # análisis, etc. en cascada), marcamos el perfil como eliminado.
    # Beneficios:
    #   - Auditoría: queda quién/cuándo se "borró"
    #   - El usuario puede pedir recuperar la cuenta dentro de N días
    #   - No se rompen FKs ni se pierden correos analizados
    # Un management command puede purgar físicamente los profile.is_deleted
    # más viejos de cierta antigüedad si se quiere limpiar la BD.
    is_deleted   = models.BooleanField(
        default=False,
        help_text="Soft delete: marca la cuenta como eliminada sin borrar los datos.",
    )
    deleted_at   = models.DateTimeField(null=True, blank=True,
                                        help_text="Cuándo se marcó la cuenta como eliminada.")
    deletion_ip  = models.GenericIPAddressField(null=True, blank=True,
                                                help_text="IP desde donde se solicitó la eliminación.")
    # ── Bloqueo por intentos fallidos de login ────────────────────────
    # Tracking PER-USER (separado del rate-limit por IP de auth_service).
    # Flujo:
    #   1) Cada contraseña incorrecta sube failed_login_attempts.
    #   2) Al llegar a LOGIN_MAX_USER_FAILS → temp_locked_until = +3 min
    #      y temp_lock_triggered = True (la siguiente falla será permanente).
    #   3) Si vuelve a fallar después de que expira el temp lock →
    #      User.is_active = False + permanent_lock_at + permanent_lock_reason.
    #   4) Login correcto resetea el contador y limpia ambos campos de lock.
    # `permanent_lock_at` se usa para distinguir bloqueo por intentos vs
    # soft delete (is_deleted). Ambos ponen User.is_active=False, pero
    # tienen UI y recuperación distintas.
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        help_text="Intentos consecutivos de password incorrecta. Se resetea al login exitoso.",
    )
    temp_locked_until = models.DateTimeField(
        null=True, blank=True,
        help_text="Si > now, la cuenta está bloqueada temporalmente.",
    )
    temp_lock_triggered = models.BooleanField(
        default=False,
        help_text="True una vez que se disparó el temp lock. La siguiente falla = bloqueo permanente.",
    )
    permanent_lock_reason = models.TextField(
        blank=True, default='',
        help_text="Motivos que se muestran al usuario en la card de cuenta bloqueada.",
    )
    permanent_lock_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Cuándo se bloqueó permanentemente la cuenta por intentos fallidos.",
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
    Código de 6 dígitos enviado al correo del usuario. Originalmente
    sirve para verificar email al registrarse, pero también se reusa
    para confirmar acciones destructivas (eliminar cuenta).

    El campo `purpose` distingue el propósito del código, para que
    códigos de registro no se puedan usar para borrar la cuenta y
    viceversa.

    Flujo registro:
      1. Usuario se registra → creamos User con is_active=False y un
         EmailVerificationCode con purpose='register'.
      2. Enviamos correo con el código.
      3. Usuario pega el código → verificamos → activamos cuenta.

    Flujo eliminación:
      1. Usuario confirma contraseña + texto "ELIMINAR" en perfil.
      2. Generamos EmailVerificationCode con purpose='delete_account'.
      3. Enviamos correo con el código (template rojo de alerta).
      4. Usuario ingresa código → marcamos profile.is_deleted=True.
    """
    PURPOSE_CHOICES = [
        ('register',       'Verificación de registro'),
        ('delete_account', 'Confirmar eliminación de cuenta'),
    ]

    user       = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='email_verification_codes',
    )
    purpose    = models.CharField(
        max_length=20, choices=PURPOSE_CHOICES, default='register', db_index=True,
        help_text='Para qué acción se usa este código.',
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


# ═══════════════════════════════════════════════════════════════════════
#  REGISTRO PENDIENTE DE VERIFICACIÓN
# ═══════════════════════════════════════════════════════════════════════

class PendingRegistration(models.Model):
    """
    Datos de un registro a la espera de verificación de correo.
    El User real NO se crea en `auth_user` hasta que el dueño del correo
    pruebe que tiene acceso al buzón ingresando el código de 6 dígitos.

    Por qué esto y no `User(is_active=False)` como antes:
      - Antes la BD se llenaba de cuentas inactivas cuando alguien
        abandonaba el flujo (cerró pestaña, no llegó el correo, error
        de tipeo, etc.). Eso ensuciaba el panel de admin y abría la
        puerta a "cuadrar" correos ajenos para reservar el username.
      - Ahora la cuenta NO existe hasta que se demuestre control del
        buzón → si el flujo se abandona, basta con borrar este row,
        nada que limpiar en cascada.

    Campos:
      - password_hash: la contraseña ya hasheada con make_password().
        Nunca guardamos texto plano.
      - code/token/expires_at/attempts: igual que EmailVerificationCode.
      - email NO es unique: permitimos varios pendientes del mismo
        correo (typos consecutivos, reintentos). Cuando uno se verifica,
        los demás del mismo email se invalidan.
    """
    email         = models.EmailField(db_index=True)
    first_name    = models.CharField(max_length=150)
    password_hash = models.CharField(
        max_length=128,
        help_text="Contraseña hasheada con django.contrib.auth.hashers.make_password.",
    )
    code          = models.CharField(max_length=6, db_index=True)
    token         = models.CharField(max_length=64, unique=True, db_index=True)
    created_at    = models.DateTimeField(auto_now_add=True)
    expires_at    = models.DateTimeField()
    used_at       = models.DateTimeField(null=True, blank=True)
    attempts      = models.PositiveSmallIntegerField(
        default=0,
        help_text="Cuántas veces se intentó verificar (anti brute-force).",
    )

    class Meta:
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


# ═══════════════════════════════════════════════════════════════════════
#  SOLICITUD DE RECUPERACIÓN DE CUENTA BLOQUEADA
# ═══════════════════════════════════════════════════════════════════════

class AccountRecoveryRequest(models.Model):
    """
    Solicitud que un usuario envía al admin para reactivar su cuenta
    después de un bloqueo PERMANENTE por intentos fallidos de login.

    Espeja la estructura de AliasQuotaRequest (aliases.models). Al
    aprobar: User.is_active=True, se limpian los campos de lock del
    profile. Al rechazar: la cuenta queda bloqueada y el usuario recibe
    una notificación con la nota del admin.

    Por usuario solo puede haber UNA pendiente — enforced en la vista.
    """
    STATUS = [
        ('pending',  'Pendiente'),
        ('approved', 'Aprobada'),
        ('rejected', 'Rechazada'),
    ]

    user        = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='account_recovery_requests',
    )
    reason      = models.TextField(
        help_text="Explicación del usuario de por qué quiere recuperar la cuenta.",
    )
    status      = models.CharField(max_length=10, choices=STATUS, default='pending')
    admin_note  = models.TextField(
        blank=True,
        help_text="Nota del admin al aprobar/rechazar (opcional).",
    )
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='resolved_account_recovery_requests',
    )
    created_at  = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Solicitud de recuperación de cuenta'
        verbose_name_plural = 'Solicitudes de recuperación de cuenta'
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self):
        return f"Recovery {self.user.email} ({self.status})"
