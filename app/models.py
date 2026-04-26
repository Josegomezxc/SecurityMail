from django.db import models

# Create your models here.
# securemail/models.py
from django.db import models
from django.contrib.auth.models import User


class Alias(models.Model):
    """Dirección de correo desechable asociada a un usuario."""
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='aliases')
    label       = models.CharField(max_length=100, help_text="Etiqueta: ej. Amazon, Foro Reddit")
    address     = models.EmailField(unique=True, help_text="Dirección generada: amazon_x7k2@securemail.app")
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
    body_html   = models.TextField(blank=True, help_text="Cuerpo HTML del correo (se renderiza en iframe sandbox)")
    received_at = models.DateTimeField(auto_now_add=True)
    read        = models.BooleanField(default=False)

    # Adjunto
    has_attachment  = models.BooleanField(default=False)
    attachment_name = models.CharField(max_length=255, blank=True)
    attachment_path = models.CharField(max_length=500, blank=True)

    # Puntuación de riesgo calculada por el sandbox
    risk_score = models.IntegerField(default=0, help_text="0-100. 0=seguro, 100=malware")

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