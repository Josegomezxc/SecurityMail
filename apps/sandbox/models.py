from django.db import models


class SandboxAnalysis(models.Model):
    RISK_LEVELS = [
        ('safe',     'Seguro (0-30)'),
        ('warning',  'Sospechoso (31-60)'),
        ('danger',   'Alto riesgo (61-80)'),
        ('malware',  'Malware (81-100)'),
    ]

    id = models.AutoField(primary_key=True, db_column='id_analisis_sandbox')
    email = models.OneToOneField(
        'mail.EmailMessage', on_delete=models.CASCADE, related_name='analysis',
        db_column='id_correo',
    )
    analyzed_at = models.DateTimeField(auto_now_add=True, db_column='ans_analizado_en')
    risk_score = models.IntegerField(default=0, db_column='ans_puntaje_riesgo')
    risk_level = models.CharField(
        max_length=10, choices=RISK_LEVELS, default='safe', db_column='ans_nivel_riesgo',
    )
    threat_name = models.CharField(max_length=200, blank=True, db_column='ans_nombre_amenaza')
    blocked = models.BooleanField(default=False, db_column='ans_bloqueado')
    is_active = models.BooleanField(default=True, db_column='ans_activo')

    def __str__(self):
        return f"{self.file_info.filename if hasattr(self, 'file_info') else '?'} - {self.risk_score}/100"

    class Meta:
        db_table = 'tbl_analisis_sandbox'
        ordering = ['-analyzed_at']
        verbose_name = 'Análisis sandbox'
        verbose_name_plural = 'Análisis sandbox'


class FileInfo(models.Model):
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

    id = models.AutoField(primary_key=True, db_column='id_info_archivo')
    analysis = models.OneToOneField(
        SandboxAnalysis, on_delete=models.CASCADE, related_name='file_info',
        db_column='id_analisis_sandbox',
    )
    filename = models.CharField(max_length=255, db_column='ifa_nombre_archivo')
    real_mime_type = models.CharField(max_length=100, blank=True, db_column='ifa_tipo_mime_real')
    sha256_hash = models.CharField(max_length=64, blank=True, db_column='ifa_hash_sha256')
    md5_hash = models.CharField(max_length=32, blank=True, db_column='ifa_hash_md5')
    file_size = models.BigIntegerField(default=0, db_column='ifa_tamano_archivo')
    extension = models.CharField(max_length=20, blank=True, db_column='ifa_extension')
    extension_spoof = models.BooleanField(
        default=False, db_column='ifa_extension_falsificada',
        help_text="La extensión no coincide con el MIME real",
    )
    is_active = models.BooleanField(default=True, db_column='ifa_activo')

    class Meta:
        db_table = 'tbl_info_archivo'


class DynamicAnalysis(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_analisis_dinamico')
    analysis = models.OneToOneField(
        SandboxAnalysis, on_delete=models.CASCADE, related_name='dynamic',
        db_column='id_analisis_sandbox',
    )
    category = models.CharField(
        max_length=20, choices=FileInfo.CATEGORIES, default='unknown', db_column='and_categoria',
    )
    yara_matches = models.JSONField(default=list, blank=True, db_column='and_coincidencias_yara')
    network_connections = models.JSONField(default=list, blank=True, db_column='and_conexiones_red')
    child_processes = models.JSONField(default=list, blank=True, db_column='and_procesos_hijos')
    file_writes = models.JSONField(default=list, blank=True, db_column='and_archivos_escritos')
    evidence = models.JSONField(
        default=list, blank=True, db_column='and_evidencia',
        help_text="Lista de indicadores con type, detail y severity",
    )
    iocs = models.JSONField(
        default=dict, blank=True, db_column='and_iocs',
        help_text="URLs, IPs, dominios y hashes detectados",
    )
    analyzers_run = models.JSONField(
        default=list, blank=True, db_column='and_analizadores_ejecutados',
        help_text="Analizadores que se ejecutaron",
    )
    is_active = models.BooleanField(default=True, db_column='and_activo')

    class Meta:
        db_table = 'tbl_analisis_dinamico'


class BodyAnalysis(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_analisis_cuerpo')
    analysis = models.OneToOneField(
        SandboxAnalysis, on_delete=models.CASCADE, related_name='body_analysis',
        db_column='id_analisis_sandbox',
    )
    body_score = models.IntegerField(
        default=0, db_column='anc_puntaje_cuerpo',
        help_text="Puntuación del análisis del cuerpo del correo",
    )
    body_evidence = models.JSONField(
        default=list, blank=True, db_column='anc_evidencia_cuerpo',
        help_text="Evidencia del análisis del cuerpo",
    )
    body_threat = models.CharField(max_length=200, blank=True, db_column='anc_amenaza_cuerpo')
    attachments_reports = models.JSONField(
        default=list, blank=True, db_column='anc_reportes_adjuntos',
        help_text="Lista de reportes por cada adjunto",
    )
    is_active = models.BooleanField(default=True, db_column='anc_activo')

    class Meta:
        db_table = 'tbl_analisis_cuerpo'


class IAResult(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_resultado_ia')
    analysis = models.OneToOneField(
        SandboxAnalysis, on_delete=models.CASCADE, related_name='ai_result',
        db_column='id_analisis_sandbox',
    )
    ai_verdict = models.CharField(
        max_length=20, blank=True, db_column='ria_veredicto_ia',
        help_text='MALICIOSO / SOSPECHOSO / SEGURO',
    )
    ai_threat_type = models.CharField(
        max_length=100, blank=True, db_column='ria_tipo_amenaza_ia',
        help_text='Tipo de amenaza (Phishing, Malware, etc.)',
    )
    ai_explanation = models.TextField(
        blank=True, db_column='ria_explicacion_ia',
        help_text='Respuesta de la IA en Markdown (EXPLICACION)',
    )
    ai_recommendation = models.TextField(
        blank=True, db_column='ria_recomendacion_ia',
        help_text='Respuesta de la IA en Markdown (RECOMENDACION)',
    )
    ai_generated_at = models.DateTimeField(
        null=True, blank=True, db_column='ria_generado_ia_en',
        help_text='Cuándo se generó el análisis IA por última vez',
    )
    is_active = models.BooleanField(default=True, db_column='ria_activo')

    class Meta:
        db_table = 'tbl_resultado_ia'
