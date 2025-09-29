"""
URLs pour l'application sales - GESTORE
Configuration des routes API pour la gestion des ventes
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    HealthCheckView,
    CustomerViewSet,
    PaymentMethodViewSet,
    DiscountViewSet,
    SaleViewSet,
    POSViewSet
)

app_name = 'sales'

# Router pour les ViewSets
router = DefaultRouter()
router.register(r'customers', CustomerViewSet, basename='customer')
router.register(r'payment-methods', PaymentMethodViewSet, basename='paymentmethod')
router.register(r'discounts', DiscountViewSet, basename='discount')
router.register(r'sales', SaleViewSet, basename='sale')
router.register(r'pos', POSViewSet, basename='pos')

urlpatterns = [
    # Health check
    path('health/', HealthCheckView.as_view(), name='health'),
    
    # Routes du router
    path('', include(router.urls)),
]