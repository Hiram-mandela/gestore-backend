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
            # CORRIGÉ: Count('user') -> Count('users') (relation définie dans migration 0002)
            users_count=Count('users', filter=Q(users__is_active=True))
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
                # CORRIGÉ: 'usersession' -> 'sessions' (relation définie dans migration 0002)
                'sessions',
                queryset=UserSession.objects.filter(
                    is_active=True,
                    login_at__gte=timezone.now() - timezone.timedelta(minutes=15)
                ),
                to_attr='recent_sessions'
            )
        ).annotate(
            # CORRIGÉ: Count('usersession') -> Count('sessions') et usersession__ -> sessions__
            _is_online=Count('sessions', filter=Q(
                sessions__is_active=True,
                sessions__login_at__gte=timezone.now() - timezone.timedelta(minutes=15)
            ))
        )
    
    def optimize_detail_queryset(self, queryset):
        """
        Optimisations pour le détail d'un utilisateur
        """
        return queryset.select_related(
            'role', 'profile', 'created_by', 'updated_by'
        ).prefetch_related(
            # CORRIGÉ: 'usersession' -> 'sessions' (relation définie dans migration 0002)
            'sessions',
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
        
        # Ne pas verrouiller les superusers
        if user.is_superuser:
            return Response(
                {'error': 'Impossible de verrouiller un superutilisateur'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Durée de verrouillage (défaut: 30 minutes)
        lock_duration = int(request.data.get('duration', 30))  # en minutes
        
        user.is_locked = True
        user.locked_until = timezone.now() + timezone.timedelta(minutes=lock_duration)
        user.save()
        
        # Terminer toutes les sessions actives
        UserSession.objects.filter(
            user=user,
            is_active=True
        ).update(
            is_active=False,
            logout_at=timezone.now()
        )
        
        # Logger l'action
        UserAuditLog.objects.create(
            user=request.user,
            action='lock_account',
            model_name='User',
            object_id=user.id,
            object_repr=str(user),
            changes={'locked_until': user.locked_until.isoformat()},
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            'message': f'Compte {user.username} verrouillé pour {lock_duration} minutes'
        })
    
    @action(detail=True, methods=['post'])
    def unlock_account(self, request, pk=None):
        """
        Déverrouiller un compte utilisateur
        """
        user = self.get_object()
        
        user.is_locked = False
        user.locked_until = None
        user.failed_login_attempts = 0
        user.save()
        
        # Logger l'action
        UserAuditLog.objects.create(
            user=request.user,
            action='unlock_account',
            model_name='User',
            object_id=user.id,
            object_repr=str(user),
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            'message': f'Compte {user.username} déverrouillé avec succès'
        })
    
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
                {'error': 'Session non trouvée ou déjà terminée'}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['get'])
    def activity_log(self, request, pk=None):
        """
        Journal d'activité d'un utilisateur
        """
        user = self.get_object()
        
        # Pagination
        page_size = int(request.query_params.get('page_size', 20))
        offset = int(request.query_params.get('offset', 0))
        
        logs = UserAuditLog.objects.filter(
            user=user
        ).order_by('-timestamp')[offset:offset + page_size]
        
        serializer = UserAuditLogSerializer(logs, many=True, context={'request': request})
        
        return Response({
            'count': UserAuditLog.objects.filter(user=user).count(),
            'results': serializer.data
        })
    
    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """
        Actions en masse sur les utilisateurs
        """
        user_ids = request.data.get('user_ids', [])
        action_type = request.data.get('action')
        
        if not user_ids or not action_type:
            return Response(
                {'error': 'user_ids et action requis'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        users = User.objects.filter(id__in=user_ids)
        updated_count = 0
        
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
        
        # Logger l'action bulk
        UserAuditLog.objects.create(
            user=request.user,
            action=f'bulk_{action_type}',
            model_name='User',
            changes={'user_ids': user_ids, 'count': updated_count},
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            'message': f'Action {action_type} appliquée avec succès',
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
        Upload d'avatar
        """
        profile = UserProfile.objects.get_or_create(user=request.user)[0]
        
        if 'avatar' not in request.FILES:
            return Response(
                {'error': 'Fichier avatar requis'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        profile.avatar = request.FILES['avatar']
        profile.save()
        
        serializer = self.get_serializer(profile)
        return Response(serializer.data)


class LoginView(TokenObtainPairView):
    """
    Vue de connexion personnalisée avec tracking des sessions
    """
    serializer_class = LoginSerializer
    
    def post(self, request, *args, **kwargs):
        """
        Connexion avec JWT et tracking session
        """
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Réinitialiser les tentatives échouées
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.save()
            
            # Générer les tokens JWT
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
                
                # CORRECTION CRITIQUE: Recharger le profile pour résoudre F()
                profile.refresh_from_db()
            
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
    