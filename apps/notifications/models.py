from django.db import models
from django.contrib.auth.models import User


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
        'mail.EmailMessage', on_delete=models.CASCADE, null=True, blank=True,
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
