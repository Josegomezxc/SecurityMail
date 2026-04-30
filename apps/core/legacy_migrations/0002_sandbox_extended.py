from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='sandboxanalysis',
            name='md5_hash',
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='file_size',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='extension',
            field=models.CharField(blank=True, max_length=20),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='extension_spoof',
            field=models.BooleanField(
                default=False,
                help_text='La extensión no coincide con el MIME real',
            ),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='category',
            field=models.CharField(
                choices=[
                    ('executable', 'Ejecutable'),
                    ('office',     'Documento Office'),
                    ('pdf',        'PDF'),
                    ('archive',    'Archivo comprimido'),
                    ('script',     'Script'),
                    ('body',       'Cuerpo del correo'),
                    ('url',        'URL'),
                    ('aggregate',  'Agregado'),
                    ('unknown',    'Desconocido'),
                ],
                default='unknown',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='evidence',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text='Lista de indicadores con type, detail y severity',
            ),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='iocs',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text='URLs, IPs, dominios y hashes detectados',
            ),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='analyzers_run',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text='Analizadores que se ejecutaron',
            ),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='body_score',
            field=models.IntegerField(
                default=0,
                help_text='Puntuación del análisis del cuerpo del correo',
            ),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='body_evidence',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text='Evidencia del análisis del cuerpo',
            ),
        ),
        migrations.AddField(
            model_name='sandboxanalysis',
            name='body_threat',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
