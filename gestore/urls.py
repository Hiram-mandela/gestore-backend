"""
Configuration des URLs principales pour GESTORE
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.utils import timezone
from rest_framework import permissions
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

def api_root(request):
    """Vue racine de l'API"""
    return JsonResponse({
        "message": "Bienvenue sur l'API GESTORE",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "admin": "/admin/",
            "api_root": "/api/",
            "api_docs": "/api/docs/",
            "api_schema": "/api/schema/",
            "health": "/api/health/",
            "auth": "/api/auth/"
        },
        "apps": {
            "core": "Configuration de base",
            "authentication": "Gestion utilisateurs et sécurité",
            "inventory": "Gestion stocks et articles",
            "sales": "Gestion ventes et point de vente",
            "suppliers": "Gestion fournisseurs et commandes",
            "reporting": "Rapports et analytics",
            "sync": "Synchronisation online/offline",
            "licensing": "Système de licence"
        }
    })

def api_health(request):
    """Vue de vérification de santé globale"""
    from django.db import connection
    
    try:
        # Test de connexion DB
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return JsonResponse({
        "status": "healthy" if db_status == "connected" else "unhealthy",
        "database": db_status,
        "apps": "loaded",
        "timestamp": timezone.now().isoformat()
    })

urlpatterns = [
    # Administration Django
    path('admin/', admin.site.urls),
    
    # API URLs
    path('api/', api_root, name='api-root'),
    path('api/health/', api_health, name='api-health'),
    
    # Documentation API
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    
    # URLs des apps - ACTIVÉES
    path('api/auth/', include('apps.authentication.urls')),
    path('api/inventory/', include('apps.inventory.urls')),
    path('api/sales/', include('apps.sales.urls')),
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