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
