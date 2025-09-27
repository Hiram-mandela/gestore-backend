"""
Vues pour l'application authentication - GESTORE
ViewSets complets avec optimisations et actions personnalisées
"""
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import login, logout, get_user_model
from django.utils import timezone
from django.db.models import Q, Prefetch, Count, F
from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from apps.core.permissions import (
    CanManageUsers, IsOwnerOrReadOnly, RoleBasedPermission
)
from .models import Role, UserProfile, UserSession, UserAuditLog
from .serializers import (
    RoleSerializer, UserSerializer, UserCreateSerializer, UserListSerializer,
    UserProfileSerializer, UserSessionSerializer, PasswordChangeSerializer,
    LoginSerializer, UserAuditLogSerializer
)

User = get_user_model()


class HealthCheckView(APIView):
    """Vue de vérification de santé pour authentication"""
    permission_classes = []
    
    def get(self, request):
        return Response({
            "status": "ok", 
            "app": "authentication",
            "users_count": User.objects.count(),
            "active_users": User.objects.filter(is_active=True).count(),
            "roles_count": Role.objects.count()
        })


class OptimizedModelViewSet(viewsets.ModelViewSet):
    """
    ViewSet de base avec optimisations communes
    """
    
    def get_queryset(self):
        """
        Optimise les requêtes selon l'action
        """
        queryset = super().get_queryset()
        
        # Optimisations spécifiques par action
        if self.action == 'list':
            return self.optimize_list_queryset(queryset)
        elif self.action == 'retrieve':
            return self.optimize_detail_queryset(queryset)
        
        return queryset
    
    def optimize_list_queryset(self, queryset):
        """
        Optimisations pour les listes (à surcharger)
        """
        return queryset
    
    def optimize_detail_queryset(self, queryset):
        """
        Optimisations pour les détails (à surcharger)
        """
        return queryset


class RoleViewSet(OptimizedModelViewSet):
    """
    ViewSet pour la gestion des rôles
    """
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [CanManageUsers]
    
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['role_type', 'is_active']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'role_type', 'created_at']
    ordering = ['role_type', 'name']
    
    def optimize_list_queryset(self, queryset):
        """
        Optimisations pour la liste des rôles
        """
        return queryset.annotate(
            users_count=Count('user', filter=Q(user__is_active=True))
        )
    
    def optimize_detail_queryset(self, queryset):
        """
        Optimisations pour le détail d'un rôle
        """
        return queryset.prefetch_related('permissions')
    
    @action(detail=True, methods=['get'])
    def users(self, request, pk=None):
        """
        Liste des utilisateurs assignés à ce rôle
        """
        role = self.get_object()
        users = User.objects.filter(role=role, is_active=True).select_related('profile')
        
        serializer = UserListSerializer(users, many=True, context={'request': request})
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def permissions(self, request):
        """
        Liste des permissions disponibles pour les rôles
        """
        permissions_list = [
            {'code': 'can_manage_users', 'name': 'Gestion utilisateurs'},
            {'code': 'can_manage_inventory', 'name': 'Gestion stocks'},
            {'code': 'can_manage_sales', 'name': 'Gestion ventes'},
            {'code': 'can_manage_suppliers', 'name': 'Gestion fournisseurs'},
            {'code': 'can_view_reports', 'name': 'Consultation rapports'},
            {'code': 'can_manage_reports', 'name': 'Gestion rapports'},
            {'code': 'can_manage_settings', 'name': 'Gestion paramètres'},
            {'code': 'can_apply_discounts', 'name': 'Application remises'},
            {'code': 'can_void_transactions', 'name': 'Annulation transactions'},
        ]
        
        return Response(permissions_list)
    
    @action(detail=True, methods=['post'])
    def clone(self, request, pk=None):
        """
        Dupliquer un rôle avec modifications
        """
        original_role = self.get_object()
        
        # Données pour le nouveau rôle
        clone_data = request.data.copy()
        clone_data['name'] = f"Copie de {original_role.name}"
        
        # Copier les permissions de l'original
        role_fields = [
            'can_manage_users', 'can_manage_inventory', 'can_manage_sales',
            'can_manage_suppliers', 'can_view_reports', 'can_manage_reports',
            'can_manage_settings', 'can_apply_discounts', 'can_void_transactions',
            'max_discount_percent'
        ]
        
        for field in role_fields:
            if field not in clone_data:
                clone_data[field] = getattr(original_role, field)
        
        serializer = self.get_serializer(data=clone_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(OptimizedModelViewSet):
    """
    ViewSet pour la gestion des utilisateurs avec optimisations
    """
    queryset = User.objects.all()
    permission_classes = [CanManageUsers]
    
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['is_active', 'role__role_type', 'department']
    search_fields = ['username', 'email', 'first_name', 'last_name', 'employee_code']
    ordering_fields = ['username', 'email', 'last_login', 'created_at']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        """
        Sélection du serializer selon l'action
        """
        if self.action == 'list':
            return UserListSerializer
        elif self.action == 'create':
            return UserCreateSerializer
        return UserSerializer
    
    def optimize_list_queryset(self, queryset):
        """
        Optimisations lourdes pour la liste des utilisateurs
        """
        return queryset.select_related(
            'role', 'profile'
        ).prefetch_related(
            Prefetch(
                'usersession',
                queryset=UserSession.objects.filter(
                    is_active=True,
                    login_at__gte=timezone.now() - timezone.timedelta(minutes=15)
                ),
                to_attr='recent_sessions'
            )
        ).annotate(
            _is_online=Count('usersession', filter=Q(
                usersession__is_active=True,
                usersession__login_at__gte=timezone.now() - timezone.timedelta(minutes=15)
            ))
        )
    
    def optimize_detail_queryset(self, queryset):
        """
        Optimisations pour le détail d'un utilisateur
        """
        return queryset.select_related(
            'role', 'profile', 'created_by', 'updated_by'
        ).prefetch_related(
            'usersession',
            'role__permissions'
        )
    
    def get_permissions(self):
        """
        Permissions spécifiques par action
        """
        if self.action == 'profile':
            return [permissions.IsAuthenticated()]
        elif self.action in ['change_password', 'update_profile']:
            return [IsOwnerOrReadOnly()]
        return super().get_permissions()
    
    @action(detail=False, methods=['get', 'patch'], permission_classes=[permissions.IsAuthenticated])
    def profile(self, request):
        """
        Profil de l'utilisateur connecté
        """
        if request.method == 'GET':
            serializer = UserSerializer(request.user, context={'request': request})
            return Response(serializer.data)
        
        elif request.method == 'PATCH':
            serializer = UserSerializer(
                request.user, 
                data=request.data, 
                partial=True,
                context={'request': request}
            )
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def change_password(self, request):
        """
        Changement de mot de passe pour l'utilisateur connecté
        """
        serializer = PasswordChangeSerializer(
            data=request.data, 
            context={'request': request}
        )
        
        if serializer.is_valid():
            serializer.save()
            
            # Déconnecter toutes les autres sessions
            UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).exclude(
                session_key=request.session.session_key
            ).update(
                is_active=False,
                logout_at=timezone.now()
            )
            
            return Response({
                'message': 'Mot de passe changé avec succès. Autres sessions déconnectées.'
            })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def lock_account(self, request, pk=None):
        """
        Verrouiller un compte utilisateur
        """
        user = self.get_object()
        duration_minutes = request.data.get('duration_minutes', 30)
        reason = request.data.get('reason', 'Verrouillage administratif')
        
        user.lock_account(duration_minutes)
        
        # Déconnecter toutes les sessions
        UserSession.objects.filter(
            user=user,
            is_active=True
        ).update(
            is_active=False,
            logout_at=timezone.now()
        )
        
        # Logger l'action
        UserAuditLog.objects.create(
            user=user,
            action='lock',
            model_name='User',
            object_id=user.id,
            object_repr=str(user),
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            changes={'reason': reason, 'duration_minutes': duration_minutes}
        )
        
        return Response({
            'message': f'Compte verrouillé pour {duration_minutes} minutes.',
            'locked_until': user.locked_until
        })
    
    @action(detail=True, methods=['post'])
    def unlock_account(self, request, pk=None):
        """
        Déverrouiller un compte utilisateur
        """
        user = self.get_object()
        user.unlock_account()
        
        # Logger l'action
        UserAuditLog.objects.create(
            user=user,
            action='unlock',
            model_name='User',
            object_id=user.id,
            object_repr=str(user),
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({'message': 'Compte déverrouillé avec succès.'})
    
    @action(detail=True, methods=['get'])
    def sessions(self, request, pk=None):
        """
        Sessions actives d'un utilisateur
        """
        user = self.get_object()
        sessions = UserSession.objects.filter(
            user=user,
            is_active=True
        ).order_by('-login_at')
        
        serializer = UserSessionSerializer(
            sessions, 
            many=True, 
            context={'request': request}
        )
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def terminate_session(self, request, pk=None):
        """
        Terminer une session spécifique
        """
        user = self.get_object()
        session_key = request.data.get('session_key')
        
        if not session_key:
            return Response(
                {'error': 'session_key requis'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        sessions_updated = UserSession.objects.filter(
            user=user,
            session_key=session_key,
            is_active=True
        ).update(
            is_active=False,
            logout_at=timezone.now()
        )
        
        if sessions_updated > 0:
            return Response({'message': 'Session terminée avec succès.'})
        else:
            return Response(
                {'error': 'Session non trouvée ou déjà inactive'}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['get'])
    def activity_log(self, request, pk=None):
        """
        Journal d'activité d'un utilisateur
        """
        user = self.get_object()
        logs = UserAuditLog.objects.filter(user=user).order_by('-timestamp')[:100]
        
        serializer = UserAuditLogSerializer(logs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """
        Actions en masse sur les utilisateurs
        """
        action_type = request.data.get('action')
        user_ids = request.data.get('user_ids', [])
        
        if not action_type or not user_ids:
            return Response(
                {'error': 'action et user_ids requis'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        users = User.objects.filter(id__in=user_ids)
        updated_count = 0
        
        with transaction.atomic():
            if action_type == 'activate':
                updated_count = users.update(is_active=True)
            elif action_type == 'deactivate':
                updated_count = users.update(is_active=False)
            elif action_type == 'unlock':
                updated_count = users.update(
                    is_locked=False, 
                    locked_until=None, 
                    failed_login_attempts=0
                )
            else:
                return Response(
                    {'error': 'Action non supportée'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response({
            'message': f'{updated_count} utilisateurs modifiés.',
            'action': action_type,
            'updated_count': updated_count
        })


class UserProfileViewSet(viewsets.ModelViewSet):
    """
    ViewSet pour la gestion des profils utilisateur
    """
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsOwnerOrReadOnly]
    
    def get_queryset(self):
        """
        Filtrer selon l'utilisateur connecté ou permissions
        """
        if self.request.user.is_superuser or (
            hasattr(self.request.user, 'role') and 
            self.request.user.role and 
            self.request.user.role.can_manage_users
        ):
            return UserProfile.objects.select_related('user')
        
        # Utilisateur normal ne voit que son profil
        return UserProfile.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get', 'patch'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        """
        Profil de l'utilisateur connecté
        """
        try:
            profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            # Créer le profil s'il n'existe pas
            profile = UserProfile.objects.create(user=request.user)
        
        if request.method == 'GET':
            serializer = self.get_serializer(profile)
            return Response(serializer.data)
        
        elif request.method == 'PATCH':
            serializer = self.get_serializer(
                profile, 
                data=request.data, 
                partial=True
            )
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def upload_avatar(self, request):
        """
        Upload d'avatar utilisateur
        """
        try:
            profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=request.user)
        
        if 'avatar' not in request.FILES:
            return Response(
                {'error': 'Fichier avatar requis'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        avatar_file = request.FILES['avatar']
        
        # Validation du fichier
        if avatar_file.size > 5 * 1024 * 1024:  # 5MB max
            return Response(
                {'error': 'Fichier trop volumineux (max 5MB)'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        allowed_types = ['image/jpeg', 'image/png', 'image/gif']
        if avatar_file.content_type not in allowed_types:
            return Response(
                {'error': 'Format non supporté (JPEG, PNG, GIF uniquement)'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Supprimer l'ancien avatar
        if profile.avatar:
            profile.avatar.delete()
        
        # Sauvegarder le nouveau
        profile.avatar = avatar_file
        profile.save()
        
        serializer = self.get_serializer(profile)
        return Response(serializer.data)


class LoginView(TokenObtainPairView):
    """
    Vue de connexion personnalisée avec tracking
    """
    
    def post(self, request, *args, **kwargs):
        """
        Connexion avec création de session et logging
        """
        serializer = LoginSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Réinitialiser les tentatives échouées
            user.reset_failed_login()
            
            # Créer les tokens JWT
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Créer une session de tracking
            user_session = UserSession.objects.create(
                user=user,
                session_key=request.session.session_key or 'api_session',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Mettre à jour les statistiques utilisateur
            user.last_login = timezone.now()
            user.save()
            
            if hasattr(user, 'profile'):
                profile = user.profile
                profile.last_login_ip = request.META.get('REMOTE_ADDR', '')
                profile.login_count = F('login_count') + 1
                profile.save()
            
            # Logger la connexion
            UserAuditLog.objects.create(
                user=user,
                action='login',
                model_name='User',
                object_id=user.id,
                object_repr=str(user),
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Préparer la réponse
            response_data = {
                'access_token': str(access_token),
                'refresh_token': str(refresh),
                'user': UserSerializer(user, context={'request': request}).data,
                'session_id': str(user_session.id)
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        else:
            # Incrémenter les tentatives échouées si utilisateur trouvé
            username = request.data.get('username')
            if username:
                try:
                    user = User.objects.get(username=username)
                    user.increment_failed_login()
                except User.DoesNotExist:
                    pass
            
            return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(viewsets.ViewSet):
    """
    Vue de déconnexion avec nettoyage des sessions
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def logout(self, request):
        """
        Déconnexion avec nettoyage
        """
        # Terminer la session de tracking
        UserSession.objects.filter(
            user=request.user,
            session_key=request.session.session_key,
            is_active=True
        ).update(
            is_active=False,
            logout_at=timezone.now()
        )
        
        # Logger la déconnexion
        UserAuditLog.objects.create(
            user=request.user,
            action='logout',
            model_name='User',
            object_id=request.user.id,
            object_repr=str(request.user),
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Nettoyer la session Django
        logout(request)
        
        return Response({'message': 'Déconnexion réussie'})
    
    @action(detail=False, methods=['post'])
    def logout_all(self, request):
        """
        Déconnexion de toutes les sessions
        """
        # Terminer toutes les sessions actives
        UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).update(
            is_active=False,
            logout_at=timezone.now()
        )
        
        # Logger l'action
        UserAuditLog.objects.create(
            user=request.user,
            action='logout_all',
            model_name='User',
            object_id=request.user.id,
            object_repr=str(request.user),
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({'message': 'Toutes les sessions ont été terminées'})
    