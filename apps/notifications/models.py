from django.db import models
from django.contrib.auth.models import User


class Notification(models.Model):
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
        ('done',     'Completada'),
    ]

    id = models.AutoField(primary_key=True, db_column='id_notificacion')
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='notifications',
        db_column='id_usuario',
    )
    type = models.CharField(max_length=20, choices=TYPES, default='system', db_index=True, db_column='ntf_tipo')
    title = models.CharField(max_length=200, db_column='ntf_titulo')
    message = models.TextField(blank=True, db_column='ntf_mensaje',
                               help_text="Preview corto, opcional")
    related_email = models.ForeignKey(
        'mail.EmailMessage', on_delete=models.CASCADE, null=True, blank=True,
        related_name='notifications', db_column='id_correo_relacionado',
        help_text="Si la notificación es sobre un correo concreto",
    )
    read = models.BooleanField(default=False, db_index=True, db_column='ntf_leido')
    status = models.CharField(max_length=12, choices=STATUSES, default='done', db_index=True, db_column='ntf_estado')
    created_at = models.DateTimeField(auto_now_add=True, db_column='ntf_creado_en')
    actioned_at = models.DateTimeField(
        null=True, blank=True, db_column='ntf_accionado_en',
        help_text="Cuándo el usuario tomó acción",
    )
    target_url = models.CharField(max_length=300, blank=True, default='', db_column='ntf_url_destino')
    is_active = models.BooleanField(default=True, db_column='ntf_activo')

    class Meta:
        db_table = 'tbl_notificacion'
        ordering = ['-created_at']
        verbose_name = 'Notificación'
        verbose_name_plural = 'Notificaciones'
        indexes = [
            models.Index(fields=['user', '-created_at'], name='notificatio_user_id_05b4bc_idx'),
            models.Index(fields=['user', 'read'], name='notificatio_user_id_878a13_idx'),
        ]

    def __str__(self):
        return f"{self.type} → {self.user.email} ({self.title[:40]})"

    @property
    def is_actionable(self) -> bool:
        return self.type == 'forward_request' and self.status == 'pending'

    @property
    def quota_amount(self):
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

        msg = self.message or ''
        if '\n\n' in msg:
            main, _, extra = msg.partition('\n\n')
            return (main.strip(), extra.strip())
        for marker in ('  Motivo: ', '  Nota: ', ' Motivo: ', ' Nota: '):
            if marker in msg:
                main, _, extra = msg.partition(marker)
                return (main.strip(), extra.strip())
        return (msg.strip(), '')
