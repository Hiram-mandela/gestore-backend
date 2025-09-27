"""
URLs pour l'application authentication - GESTORE
Configuration complète des endpoints d'authentification
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = 'authentication'

# Router pour les ViewSets
router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='user')
router.register(r'roles', views.RoleViewSet, basename='role')
router.register(r'profiles', views.UserProfileViewSet, basename='profile')
router.register(r'logout', views.LogoutView, basename='logout')

urlpatterns = [
    # Authentification JWT
    path('login/', views.LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # ViewSets via router
    path('', include(router.urls)),
    
    # Health check pour l'app authentication
    path('health/', views.HealthCheckView.as_view(), name='auth-health'),
]