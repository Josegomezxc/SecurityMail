from django.db import migrations


def apply_unique_constraint(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor == "sqlite":
        schema_editor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS auth_user_email_key ON auth_user (email);"
        )
    else:
        schema_editor.execute(
            "ALTER TABLE auth_user ADD CONSTRAINT auth_user_email_key UNIQUE (email);"
        )


def reverse_unique_constraint(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor == "sqlite":
        schema_editor.execute("DROP INDEX IF EXISTS auth_user_email_key;")
    else:
        schema_editor.execute(
            "ALTER TABLE auth_user DROP CONSTRAINT IF EXISTS auth_user_email_key;"
        )


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0005_userprofile_malicious_attempt_data"),
    ]

    operations = [
        migrations.RunPython(apply_unique_constraint, reverse_code=reverse_unique_constraint, atomic=False),
    ]
