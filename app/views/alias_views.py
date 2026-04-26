"""
Vistas CRUD de alias desechables:
  - Lista con búsqueda y filtros.
  - Crear nuevo alias.
  - Destruir (marcar inactivo).
"""
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from ..models import Alias
from ..services.alias_service import generate_alias_address


@login_required(login_url='login')
def alias_list_view(request):
    """
    Lista todos los alias del usuario con sus contadores anotados
    (correos totales, amenazas) para la UI.
    """
    # Ojo: los nombres de anotaciones NO pueden empezar con "_"
    # porque Django templates rechaza variables con underscore inicial.
    aliases = Alias.objects.filter(user=request.user).annotate(
        emails_total  = Count('emails'),
        threats_total = Count('emails', filter=Q(emails__risk_score__gte=61)),
    ).order_by('-created_at')

    active_count    = sum(1 for a in aliases if a.is_active)
    destroyed_count = sum(1 for a in aliases if not a.is_active)
    total_emails    = sum(a.emails_total for a in aliases)
    total_threats   = sum(a.threats_total for a in aliases)

    return render(request, 'alias.html', {
        'aliases':         aliases,
        'active_count':    active_count,
        'destroyed_count': destroyed_count,
        'total_emails':    total_emails,
        'total_threats':   total_threats,
    })


@login_required(login_url='login')
def alias_create_view(request):
    """Crea un nuevo alias con una dirección única generada."""
    if request.method == 'POST':
        label = (request.POST.get('label') or '').strip()
        if not label:
            messages.error(request, 'Ingresa una etiqueta para el alias.')
            return redirect('alias_list')

        address = generate_alias_address(label)

        Alias.objects.create(
            user=request.user,
            label=label,
            address=address,
        )
        messages.success(request, f'Alias creado: {address}')

    return redirect('alias_list')


@login_required(login_url='login')
def alias_destroy_view(request, pk):
    """Marca un alias como inactivo (soft delete)."""
    alias = get_object_or_404(Alias, pk=pk, user=request.user)
    if request.method == 'POST':
        alias.is_active   = False
        alias.destroyed_at = timezone.now()
        alias.save()
        messages.success(
            request, f'Alias {alias.address} destruido correctamente.',
        )
    return redirect('alias_list')
