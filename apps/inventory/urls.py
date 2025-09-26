"""
URLs pour l'application inventory
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'inventory'

router = DefaultRouter()
router.register(r'articles', views.ArticleViewSet)
router.register(r'categories', views.CategoryViewSet)
router.register(r'movements', views.StockMovementViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('alerts/', views.StockAlertListView.as_view(), name='stock-alerts'),
    path('search/', views.ArticleSearchView.as_view(), name='article-search'),
]
