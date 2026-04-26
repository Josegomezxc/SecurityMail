from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0002_sandbox_extended'),
    ]

    operations = [
        migrations.AddField(
            model_name='sandboxanalysis',
            name='attachments_reports',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "Lista de reportes por cada adjunto "
                    "[{filename, size, mime, sha256, score, level, threat, "
                    " evidence[], iocs{}}, ...]"
                ),
            ),
        ),
    ]
