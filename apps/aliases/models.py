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


class AliasQuotaRequest(models.Model):
    """
    Solicitud de un usuario para que el administrador le suba el límite de
    alias activos. El admin aprueba (con un monto extra que se suma al
    UserProfile.alias_quota_extra) o rechaza con una nota.

    Por usuario solo puede haber UNA solicitud `pending` a la vez —
    enforced en la vista (no aquí) para poder mostrar mejor el error.
    """
    STATUS = [
        ('pending',  'Pendiente'),
        ('approved', 'Aprobada'),
        ('rejected', 'Rechazada'),
    ]

    user             = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='alias_quota_requests',
    )
    requested_amount = models.PositiveIntegerField(
        help_text="Cuántos alias EXTRA pide el usuario (1-10).",
    )
    reason           = models.TextField(
        blank=True,
        help_text="Justificación opcional del usuario.",
    )
    status           = models.CharField(max_length=10, choices=STATUS, default='pending')
    admin_note       = models.TextField(
        blank=True,
        help_text="Nota del admin al aprobar/rechazar (opcional).",
    )
    granted_amount   = models.PositiveIntegerField(
        default=0,
        help_text="Cuánto le concedió el admin al aprobar. 0 si fue rechazada.",
    )
    resolved_by      = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='resolved_alias_requests',
    )
    created_at       = models.DateTimeField(auto_now_add=True)
    resolved_at      = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Solicitud de cupo de alias'
        verbose_name_plural = 'Solicitudes de cupo de alias'
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self):
        return f"{self.user.email} pide +{self.requested_amount} ({self.status})"
