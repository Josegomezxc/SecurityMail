from django.db import models


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

    email       = models.OneToOneField(
        'mail.EmailMessage', on_delete=models.CASCADE, related_name='analysis',
    )
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

    # ── Cache del análisis IA (Groq) ────────────────────────────────────
    # La sección "Análisis IA" del reporte llama al modelo SOLO una vez
    # por reporte. Una vez generada la respuesta, se guarda acá y futuras
    # visitas al mismo reporte reusan el cache sin tocar la API. Esto
    # ahorra cuota diaria de tokens drásticamente.
    ai_verdict      = models.CharField(max_length=20, blank=True,
                                       help_text='MALICIOSO / SOSPECHOSO / SEGURO')
    ai_threat_type  = models.CharField(max_length=100, blank=True,
                                       help_text='Tipo de amenaza (Phishing, Malware, etc.)')
    ai_explanation  = models.TextField(blank=True,
                                       help_text='Respuesta de la IA en Markdown (EXPLICACION)')
    ai_recommendation = models.TextField(blank=True,
                                         help_text='Respuesta de la IA en Markdown (RECOMENDACION)')
    ai_generated_at = models.DateTimeField(null=True, blank=True,
                                           help_text='Cuándo se generó el análisis IA por última vez')

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
