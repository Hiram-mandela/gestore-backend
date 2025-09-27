"""
Configuration des URLs principales pour GESTORE
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse

def api_root(request):
    """Vue racine de l'API"""
    return JsonResponse({
        "message": "Bienvenue sur l'API GESTORE",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "admin": "/admin/",
            "api_root": "/api/",
            "health": "/api/health/",
        },
        "apps": {
            "core": "Configuration de base",
            "authentication": "Gestion utilisateurs",
            "inventory": "Gestion stocks",
            "sales": "Gestion ventes",
            "suppliers": "Gestion fournisseurs",
            "reporting": "Rapports et analytics",
            "sync": "Synchronisation",
            "licensing": "Système de licence"
        }
    })

def api_health(request):
    """Vue de vérification de santé"""
    return JsonResponse({
        "status": "healthy",
        "database": "connected",
        "apps": "loaded",
        "timestamp": str(request.timestamp) if hasattr(request, 'timestamp') else "unknown"
    })

urlpatterns = [
    # Administration Django
    path('admin/', admin.site.urls),
    
    # API URLs
    path('api/', api_root, name='api-root'),
    path('api/health/', api_health, name='api-health'),
    
    # URLs des apps (à activer progressivement)
    # path('api/auth/', include('apps.authentication.urls')),
    # path('api/inventory/', include('apps.inventory.urls')),
    # path('api/sales/', include('apps.sales.urls')),
    # path('api/suppliers/', include('apps.suppliers.urls')),
    # path('api/reporting/', include('apps.reporting.urls')),
    # path('api/sync/', include('apps.sync.urls')),
    # path('api/licensing/', include('apps.licensing.urls')),
]

# Configuration pour développement
if settings.DEBUG:
    # Fichiers statiques et media
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar (seulement si installé)
    try:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include('debug_toolbar.urls')),
        ] + urlpatterns
    except ImportError:
        # Debug toolbar non installé, on continue sans
        pass
