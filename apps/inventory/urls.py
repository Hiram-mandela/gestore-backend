"""
URLs pour l'application inventory - GESTORE
Configuration des routes API pour la gestion des stocks
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    HealthCheckView,
    UnitOfMeasureViewSet,
    UnitConversionViewSet,
    CategoryViewSet,
    BrandViewSet,
    SupplierViewSet,
    ArticleViewSet,
    LocationViewSet,
    StockViewSet,
    StockMovementViewSet,
    StockAlertViewSet
)

app_name = 'inventory'

# Router pour les ViewSets
router = DefaultRouter()
router.register(r'units', UnitOfMeasureViewSet, basename='unit')
router.register(r'conversions', UnitConversionViewSet, basename='conversion')
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'brands', BrandViewSet, basename='brand')
router.register(r'suppliers', SupplierViewSet, basename='supplier')
router.register(r'articles', ArticleViewSet, basename='article')
router.register(r'locations', LocationViewSet, basename='location')
router.register(r'stocks', StockViewSet, basename='stock')
router.register(r'movements', StockMovementViewSet, basename='movement')
router.register(r'alerts', StockAlertViewSet, basename='alert')

urlpatterns = [
    # Health check
    path('health/', HealthCheckView.as_view(), name='health'),
    
    # Routes du router
    path('', include(router.urls)),
]