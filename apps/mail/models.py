from django.db import models


class EmailMessage(models.Model):
    """Correo recibido en un alias."""
    alias       = models.ForeignKey(
        'aliases.Alias', on_delete=models.CASCADE, related_name='emails',
    )
    from_email  = models.EmailField()
    subject     = models.CharField(max_length=255)
    body        = models.TextField(blank=True, help_text="Cuerpo en texto plano (para preview y análisis)")
    body_html   = models.TextField(blank=True, help_text="HTML neutralizado (links/imágenes bloqueados — se muestra en la bandeja)")
    body_html_raw = models.TextField(blank=True, help_text="HTML ORIGINAL sin neutralizar (se usa al reenviar al correo real)")
    received_at = models.DateTimeField(auto_now_add=True)
    read        = models.BooleanField(default=False)

    # Soft delete: si deleted_at está seteado, el correo está en papelera.
    # Un job/auto-cleanup lo elimina permanentemente tras 30 días.
    deleted_at  = models.DateTimeField(null=True, blank=True, db_index=True,
                                       help_text="Si está seteado, el correo está en papelera")

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


class SentEmail(models.Model):
    """Correo enviado desde un alias. Se guarda como histórico ('Enviados')
    al confirmarse el envío vía SendGrid. No incluye los archivos adjuntos
    binarios — solo el conteo, ya que los archivos viajaron al destinatario.
    """
    alias       = models.ForeignKey(
        'aliases.Alias', on_delete=models.CASCADE, related_name='sent_emails',
    )
    # Lista de destinatarios separada por comas (envíos grupales).
    # Tope 2500 chars ≈ 50 correos largos — más que suficiente.
    to_email    = models.CharField(max_length=2500)
    subject     = models.CharField(max_length=255, blank=True)
    body_html   = models.TextField(blank=True, help_text="HTML enviado (ya saneado)")
    sent_at     = models.DateTimeField(auto_now_add=True)
    scheduled_at = models.DateTimeField(null=True, blank=True,
                                        help_text="Para envíos programados (send_at SendGrid)")
    attachments_count = models.IntegerField(default=0)
    # Lista de {filename, size, type} de los adjuntos enviados.
    # No guardamos el contenido (ya viajó al destinatario), solo la metadata
    # para mostrarla en la vista de detalle del correo enviado.
    attachments_meta = models.JSONField(default=list, blank=True)

    # Soft delete: ver EmailMessage.deleted_at
    deleted_at  = models.DateTimeField(null=True, blank=True, db_index=True,
                                       help_text="Si está seteado, el correo está en papelera")

    def __str__(self):
        return f"{self.subject or '(sin asunto)'} → {self.to_email}"

    class Meta:
        ordering = ['-sent_at']
        verbose_name = 'Correo enviado'
        verbose_name_plural = 'Correos enviados'


class Draft(models.Model):
    """Borrador de correo. Se crea/actualiza cuando el usuario empieza a
    escribir en el compose modal y lo cierra sin enviar (estilo Gmail).
    """
    user        = models.ForeignKey(
        'auth.User', on_delete=models.CASCADE, related_name='drafts',
    )
    # Alias opcional: el usuario puede dejar el borrador sin elegir alias
    # todavía, o el alias podría haber sido destruido después.
    alias       = models.ForeignKey(
        'aliases.Alias', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='drafts',
    )
    to_email    = models.CharField(max_length=255, blank=True)
    subject     = models.CharField(max_length=255, blank=True)
    body_html   = models.TextField(blank=True)
    scheduled_at = models.DateTimeField(null=True, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True, db_index=True)

    # Soft delete: si deleted_at != null, está en papelera (se borra a los 30 días)
    deleted_at  = models.DateTimeField(null=True, blank=True, db_index=True)

    def __str__(self):
        return f"Borrador: {self.subject or '(sin asunto)'} → {self.to_email or '(sin destinatario)'}"

    class Meta:
        ordering = ['-updated_at']
        verbose_name = 'Borrador'
        verbose_name_plural = 'Borradores'
