from django.db import models
from django.contrib.auth.models import User


class Alias(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_alias')
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='aliases', db_column='id_usuario',
    )
    label = models.CharField(
        max_length=100, db_column='ali_etiqueta',
        help_text="Etiqueta: ej. Amazon, Foro Reddit",
    )
    address = models.EmailField(
        unique=True, db_column='ali_direccion',
        help_text="Dirección generada: amazon_x7k2@dockershield.lat",
    )
    is_active = models.BooleanField(default=True, db_index=True, db_column='ali_activo')
    created_at = models.DateTimeField(auto_now_add=True, db_column='ali_creado_en')
    destroyed_at = models.DateTimeField(null=True, blank=True, db_column='ali_destruido_en')

    def __str__(self):
        return f"{self.address} ({self.label})"

    class Meta:
        db_table = 'tbl_alias'
        ordering = ['-created_at']
        verbose_name = 'Alias'
        verbose_name_plural = 'Alias'


class AliasQuotaRequest(models.Model):
    STATUS = [
        ('pending',  'Pendiente'),
        ('approved', 'Aprobada'),
        ('rejected', 'Rechazada'),
    ]

    id = models.AutoField(primary_key=True, db_column='id_solicitud_cupo_alias')
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='alias_quota_requests',
        db_column='id_usuario',
    )
    requested_amount = models.PositiveIntegerField(
        db_column='sca_cantidad_solicitada',
        help_text="Cuántos alias EXTRA pide el usuario (1-10).",
    )
    reason = models.TextField(
        blank=True, db_column='sca_motivo',
        help_text="Justificación opcional del usuario.",
    )
    status = models.CharField(
        max_length=10, choices=STATUS, default='pending', db_column='sca_estado',
    )
    admin_note = models.TextField(
        blank=True, db_column='sca_nota_admin',
        help_text="Nota del admin al aprobar/rechazar (opcional).",
    )
    granted_amount = models.PositiveIntegerField(
        default=0, db_column='sca_cantidad_concedida',
        help_text="Cuánto le concedió el admin al aprobar. 0 si fue rechazada.",
    )
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='resolved_alias_requests', db_column='id_resuelto_por',
    )
    created_at = models.DateTimeField(auto_now_add=True, db_column='sca_creado_en')
    resolved_at = models.DateTimeField(null=True, blank=True, db_column='sca_resuelto_en')
    is_active = models.BooleanField(default=True, db_column='sca_activo')

    class Meta:
        db_table = 'tbl_solicitud_cupo_alias'
        ordering = ['-created_at']
        verbose_name = 'Solicitud de cupo de alias'
        verbose_name_plural = 'Solicitudes de cupo de alias'
        indexes = [
            models.Index(fields=['status', '-created_at'], name='aliases_ali_status_b36bcd_idx'),
            models.Index(fields=['user', '-created_at'], name='aliases_ali_user_id_77a675_idx'),
        ]

    def __str__(self):
        return f"{self.user.email} pide +{self.requested_amount} ({self.status})"
