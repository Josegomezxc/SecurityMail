from django.db import models

# Create your models here.
# dockershield/models.py
from django.db import models
from django.contrib.auth.models import User


class Alias(models.Model):
    """Dirección de correo desechable asociada a un usuario."""
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='aliases')
    label       = models.CharField(max_length=100, help_text="Etiqueta: ej. Amazon, Foro Reddit")
    address     = models.EmailField(unique=True, help_text="Dirección generada: amazon_x7k2@dockershield.lat")
    is_active   = models.BooleanField(default=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    destroyed_at = models.DateTimeField(null=True, blank=True)

    @property
    def email_count(self):
        return self.emails.count()

    def __str__(self):
        return f"{self.address} ({self.label})"

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Alias'
        verbose_name_plural = 'Alias'


class EmailMessage(models.Model):
    """Correo recibido en un alias."""
    alias       = models.ForeignKey(Alias, on_delete=models.CASCADE, related_name='emails')
    from_email  = models.EmailField()
    subject     = models.CharField(max_length=255)
    body        = models.TextField(blank=True, help_text="Cuerpo en texto plano (para preview y análisis)")
    body_html   = models.TextField(blank=True, help_text="HTML neutralizado (links/imágenes bloqueados — se muestra en la bandeja)")
    body_html_raw = models.TextField(blank=True, help_text="HTML ORIGINAL sin neutralizar (se usa al reenviar al correo real)")
    received_at = models.DateTimeField(auto_now_add=True)
    read        = models.BooleanField(default=False)

    # Adjunto
    has_attachment  = models.BooleanField(default=False)
    attachment_name = models.CharField(max_length=255, blank=True)
    attachment_path = models.CharField(max_length=500, blank=True)

    # Puntuación de riesgo calculada por el sandbox
    risk_score = models.IntegerField(default=0, help_text="0-100. 0=seguro, 100=malware")

    # ── Verificación de autenticidad (SPF/DKIM/DMARC) ──
    # Resultados que SendGrid Inbound Parse calcula automáticamente y nos
    # entrega en el POST. Sirven para distinguir correos legítimos (Netflix,
    # Google, etc.) de phishers que solo escriben "From: support@netflix.com"
    # sin tener la clave privada del dominio.
    AUTH_VERDICTS = [
        ('verified',   'Verificado criptográficamente'),
        ('unverified', 'Sin verificar'),
        ('spoofed',    'Suplantación detectada'),
    ]
    auth_verdict   = models.CharField(max_length=12, choices=AUTH_VERDICTS,
                                      default='unverified', blank=True)
    auth_spf       = models.CharField(max_length=10, blank=True,
                                      help_text="pass / fail / softfail / neutral / none")
    auth_dkim      = models.CharField(max_length=10, blank=True,
                                      help_text="pass / fail / none")
    auth_dmarc     = models.CharField(max_length=10, blank=True,
                                      help_text="pass / fail / none")
    auth_signed_by = models.CharField(max_length=120, blank=True,
                                      help_text="Dominio que firmó con DKIM (header.d=)")

    def __str__(self):
        return f"{self.subject} → {self.alias.address}"

    class Meta:
        ordering = ['-received_at']
        verbose_name = 'Correo recibido'
        verbose_name_plural = 'Correos recibidos'


class SandboxAnalysis(models.Model):
    """Resultado del análisis sandbox para un adjunto."""

    RISK_LEVELS = [
        ('safe',     'Seguro (0–30)'),
        ('warning',  'Sospechoso (31–60)'),
        ('danger',   'Alto riesgo (61–80)'),
        ('malware',  'Malware (81–100)'),
    ]

    CATEGORIES = [
        ('executable', 'Ejecutable'),
        ('office',     'Documento Office'),
        ('pdf',        'PDF'),
        ('archive',    'Archivo comprimido'),
        ('script',     'Script'),
        ('body',       'Cuerpo del correo'),
        ('url',        'URL'),
        ('aggregate',  'Agregado'),
        ('unknown',    'Desconocido'),
    ]

    email       = models.OneToOneField(EmailMessage, on_delete=models.CASCADE, related_name='analysis')
    filename    = models.CharField(max_length=255)
    analyzed_at = models.DateTimeField(auto_now_add=True)

    # Identificación del archivo
    real_mime_type   = models.CharField(max_length=100, blank=True)
    sha256_hash      = models.CharField(max_length=64,  blank=True)
    md5_hash         = models.CharField(max_length=32,  blank=True)
    file_size        = models.BigIntegerField(default=0)
    extension        = models.CharField(max_length=20,  blank=True)
    extension_spoof  = models.BooleanField(default=False, help_text="La extensión no coincide con el MIME real")

    # Análisis estático
    yara_matches     = models.JSONField(default=list, blank=True)
    category         = models.CharField(max_length=20, choices=CATEGORIES, default='unknown')

    # Análisis dinámico (mantenidos por compatibilidad con el reporte legacy)
    network_connections = models.JSONField(default=list, blank=True)
    child_processes     = models.JSONField(default=list, blank=True)
    file_writes         = models.JSONField(default=list, blank=True)

    # Reporte estructurado nuevo
    evidence       = models.JSONField(default=list, blank=True,
                                      help_text="Lista de indicadores con type, detail y severity")
    iocs           = models.JSONField(default=dict, blank=True,
                                      help_text="URLs, IPs, dominios y hashes detectados")
    analyzers_run  = models.JSONField(default=list, blank=True,
                                      help_text="Analizadores que se ejecutaron")

    # Análisis del cuerpo del correo (no del adjunto)
    body_score     = models.IntegerField(default=0,
                                         help_text="Puntuación del análisis del cuerpo del correo")
    body_evidence  = models.JSONField(default=list, blank=True,
                                      help_text="Evidencia del análisis del cuerpo")
    body_threat    = models.CharField(max_length=200, blank=True)

    # Si el correo traía varios adjuntos, aquí van los reportes individuales
    # de cada uno. El `risk_score` y el `threat_name` arriba son el veredicto
    # AGREGADO (peor caso + evidencia fusionada).
    attachments_reports = models.JSONField(default=list, blank=True,
                                           help_text="Lista de reportes por cada adjunto "
                                                     "[{filename, size, mime, sha256, score, "
                                                     " level, threat, evidence[], iocs{}}, ...]")

    # Resultado final
    risk_score  = models.IntegerField(default=0)
    risk_level  = models.CharField(max_length=10, choices=RISK_LEVELS, default='safe')
    threat_name = models.CharField(max_length=200, blank=True)
    blocked     = models.BooleanField(default=False)

    def set_risk_level(self):
        if self.risk_score <= 30:
            self.risk_level = 'safe'
        elif self.risk_score <= 60:
            self.risk_level = 'warning'
        elif self.risk_score <= 80:
            self.risk_level = 'danger'
        else:
            self.risk_level = 'malware'
            self.blocked = True

    def __str__(self):
        return f"{self.filename} — {self.risk_score}/100"

    class Meta:
        ordering = ['-analyzed_at']
        verbose_name = 'Análisis sandbox'
        verbose_name_plural = 'Análisis sandbox'


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
#  NOTIFICACIONES (panel de campana)
# ═══════════════════════════════════════════════════════════════════════

class Notification(models.Model):
    """
    Notificaciones para el panel de campana.
    Tipos:
      forward_request: correo seguro pendiente de decisión (reenviar/descartar)
      forwarded:       correo ya reenviado al correo real (auto-forward)
      threat_alert:    amenaza detectada y bloqueada
      system:          mensajes generales del sistema
    """
    TYPES = [
        ('forward_request', 'Pendiente de aprobación'),
        ('forwarded',       'Reenviado'),
        ('threat_alert',    'Amenaza bloqueada'),
        ('system',          'Sistema'),
    ]
    STATUSES = [
        ('pending',  'Pendiente'),
        ('approved', 'Aprobada — reenviada'),
        ('discarded','Descartada'),
        ('expired',  'Expirada'),
        ('done',     'Completada'),    # threat_alert / forwarded / system
    ]

    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    type        = models.CharField(max_length=20, choices=TYPES, default='system')
    title       = models.CharField(max_length=200)
    message     = models.TextField(blank=True, help_text="Preview corto, opcional")
    related_email = models.ForeignKey(
        EmailMessage, on_delete=models.CASCADE, null=True, blank=True,
        related_name='notifications',
        help_text="Si la notificación es sobre un correo concreto",
    )
    read        = models.BooleanField(default=False)
    status      = models.CharField(max_length=12, choices=STATUSES, default='done')
    created_at  = models.DateTimeField(auto_now_add=True)
    actioned_at = models.DateTimeField(null=True, blank=True,
                                       help_text="Cuándo el usuario tomó acción")

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Notificación'
        verbose_name_plural = 'Notificaciones'
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['user', 'read']),
        ]

    def __str__(self):
        return f"{self.type} → {self.user.email} ({self.title[:40]})"

    @property
    def is_actionable(self) -> bool:
        """¿Requiere acción del usuario? (forward_request pendiente)"""
        return self.type == 'forward_request' and self.status == 'pending'


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