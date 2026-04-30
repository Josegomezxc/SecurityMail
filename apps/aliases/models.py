from django.db import models
from django.contrib.auth.models import User


class Alias(models.Model):
    """Dirección de correo desechable asociada a un usuario."""
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='aliases')
    label       = models.CharField(max_length=100, help_text="Etiqueta: ej. Amazon, Foro Reddit")
    address     = models.EmailField(unique=True, help_text="Dirección generada: amazon_x7k2@dockershield.lat")
    is_active   = models.BooleanField(default=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    destroyed_at = models.DateTimeField(null=True, blank=True)

    @property
    def email_count(self):
        return self.emails.count()

    def __str__(self):
        return f"{self.address} ({self.label})"

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Alias'
        verbose_name_plural = 'Alias'
