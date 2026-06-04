from django.db import models


class EmailMessage(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_mensaje_correo')
    alias = models.ForeignKey(
        'aliases.Alias', on_delete=models.CASCADE, related_name='emails',
        db_column='id_alias',
    )
    from_email = models.EmailField(db_column='correo_remitente')
    subject = models.CharField(max_length=255, db_column='asunto')
    body = models.TextField(
        blank=True, db_column='cuerpo',
        help_text="Cuerpo en texto plano (para preview y análisis)",
    )
    body_html = models.TextField(
        blank=True, db_column='cuerpo_html',
        help_text="HTML neutralizado (links/imágenes bloqueados - se muestra en la bandeja)",
    )
    body_html_raw = models.TextField(
        blank=True, db_column='cuerpo_html_original',
        help_text="HTML ORIGINAL sin neutralizar (se usa al reenviar al correo real)",
    )
    received_at = models.DateTimeField(auto_now_add=True, db_column='recibido_en')
    read = models.BooleanField(default=False, db_column='leido')
    deleted_at = models.DateTimeField(
        null=True, blank=True, db_index=True, db_column='eliminado_en',
        help_text="Si está seteado, el correo está en papelera",
    )
    risk_score = models.IntegerField(
        default=0, db_column='puntaje_riesgo',
        help_text="0-100. 0=seguro, 100=malware",
    )
    is_active = models.BooleanField(default=True, db_column='activo')

    def __str__(self):
        return f"{self.subject} → {self.alias.address}"

    class Meta:
        db_table = 'tbl_mensaje_correo'
        ordering = ['-received_at']
        verbose_name = 'Correo recibido'
        verbose_name_plural = 'Correos recibidos'


class EmailAuthVerdict(models.Model):
    AUTH_VERDICTS = [
        ('verified',   'Verificado criptográficamente'),
        ('unverified', 'Sin verificar'),
        ('spoofed',    'Suplantación detectada'),
    ]

    id = models.AutoField(primary_key=True, db_column='id_verificacion_correo')
    email = models.OneToOneField(
        EmailMessage, on_delete=models.CASCADE, related_name='auth',
        db_column='id_mensaje_correo',
    )
    auth_verdict = models.CharField(
        max_length=12, choices=AUTH_VERDICTS, default='unverified', blank=True,
        db_column='veredicto_auth',
    )
    auth_spf = models.CharField(
        max_length=10, blank=True, db_column='auth_spf',
        help_text="pass / fail / softfail / neutral / none",
    )
    auth_dkim = models.CharField(
        max_length=10, blank=True, db_column='auth_dkim',
        help_text="pass / fail / none",
    )
    auth_dmarc = models.CharField(
        max_length=10, blank=True, db_column='auth_dmarc',
        help_text="pass / fail / none",
    )
    auth_signed_by = models.CharField(
        max_length=120, blank=True, db_column='firmado_por',
        help_text="Dominio que firmó con DKIM (header.d=)",
    )
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_verificacion_correo'


class EmailAttachment(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_adjunto_correo')
    email = models.OneToOneField(
        EmailMessage, on_delete=models.CASCADE, related_name='attachment',
        db_column='id_mensaje_correo',
    )
    has_attachment = models.BooleanField(default=False, db_column='tiene_adjunto')
    attachment_name = models.CharField(max_length=255, blank=True, db_column='nombre_adjunto')
    attachment_path = models.CharField(max_length=500, blank=True, db_column='ruta_adjunto')
    is_active = models.BooleanField(default=True, db_column='activo')

    class Meta:
        db_table = 'tbl_adjunto_correo'


class SentEmail(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_correo_enviado')
    alias = models.ForeignKey(
        'aliases.Alias', on_delete=models.CASCADE, related_name='sent_emails',
        db_column='id_alias',
    )
    to_email = models.CharField(max_length=2500, db_column='destinatarios')
    subject = models.CharField(max_length=255, blank=True, db_column='asunto')
    body_html = models.TextField(blank=True, db_column='cuerpo_html',
                                 help_text="HTML enviado (ya saneado)")
    sent_at = models.DateTimeField(auto_now_add=True, db_column='enviado_en')
    scheduled_at = models.DateTimeField(
        null=True, blank=True, db_column='programado_en',
        help_text="Para envíos programados (send_at SendGrid)",
    )
    attachments_count = models.IntegerField(default=0, db_column='cantidad_adjuntos')
    attachments_meta = models.JSONField(default=list, blank=True, db_column='metadatos_adjuntos')
    deleted_at = models.DateTimeField(
        null=True, blank=True, db_index=True, db_column='eliminado_en',
        help_text="Si está seteado, el correo está en papelera",
    )
    is_active = models.BooleanField(default=True, db_column='activo')

    def __str__(self):
        return f"{self.subject or '(sin asunto)'} → {self.to_email}"

    class Meta:
        db_table = 'tbl_correo_enviado'
        ordering = ['-sent_at']
        verbose_name = 'Correo enviado'
        verbose_name_plural = 'Correos enviados'


class Draft(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_borrador')
    user = models.ForeignKey(
        'auth.User', on_delete=models.CASCADE, related_name='drafts',
        db_column='id_usuario',
    )
    alias = models.ForeignKey(
        'aliases.Alias', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='drafts', db_column='id_alias',
    )
    to_email = models.CharField(max_length=255, blank=True, db_column='destinatarios')
    subject = models.CharField(max_length=255, blank=True, db_column='asunto')
    body_html = models.TextField(blank=True, db_column='cuerpo_html')
    scheduled_at = models.DateTimeField(null=True, blank=True, db_column='programado_en')
    created_at = models.DateTimeField(auto_now_add=True, db_column='creado_en')
    updated_at = models.DateTimeField(auto_now=True, db_index=True, db_column='actualizado_en')
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True, db_column='eliminado_en')
    is_active = models.BooleanField(default=True, db_column='activo')

    def __str__(self):
        return f"Borrador: {self.subject or '(sin asunto)'} → {self.to_email or '(sin destinatario)'}"

    class Meta:
        db_table = 'tbl_borrador'
        ordering = ['-updated_at']
        verbose_name = 'Borrador'
        verbose_name_plural = 'Borradores'
