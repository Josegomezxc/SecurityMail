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
    # Deep-link opcional: si está, el click del toast/bell lleva acá en
    # vez de a la vista de detalle. Útil para notificaciones que apuntan
    # a páginas administrativas (ej. solicitudes de cupo) o secciones
    # específicas con query params.
    target_url  = models.CharField(max_length=300, blank=True, default='')

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

    @property
    def quota_amount(self):
        """
        Si la notificación es sobre una solicitud de cupo de alias, devuelve
        un dict con `{kind, amount}` para que el template pinte un bloque
        destacado con el número grande. None si no aplica.
            kind = 'approved' | 'rejected'
            amount = int — alias concedidos (0 si rechazada)
        """
        import re
        title = (self.title or '').lower()
        if 'aprobada' in title:
            m = re.search(r'\+(\d+)\s*alias', self.message or '')
            return {'kind': 'approved', 'amount': int(m.group(1)) if m else 0}
        if 'rechazada' in title:
            return {'kind': 'rejected', 'amount': 0}
        return None

    @property
    def message_parts(self):
        """
        Divide el mensaje en (cuerpo_principal, nota_extra) — útil cuando
        la notificación lleva una nota del admin que debe renderizarse
        aparte. Convención: separador '\\n\\n'. Para notificaciones
        viejas (sin el separador) detectamos los prefijos 'Motivo:' o
        'Nota:' que usaba el formato anterior — así no rompemos las
        notificaciones ya guardadas en BD.
        Devuelve (main, extra) — extra puede ser '' si no hay nota.
        """
        msg = self.message or ''
        if '\n\n' in msg:
            main, _, extra = msg.partition('\n\n')
            return (main.strip(), extra.strip())
        # Compatibilidad con formato viejo "Tu solicitud... Motivo: …"
        for marker in ('  Motivo: ', '  Nota: ', ' Motivo: ', ' Nota: '):
            if marker in msg:
                main, _, extra = msg.partition(marker)
                return (main.strip(), extra.strip())
        return (msg.strip(), '')
