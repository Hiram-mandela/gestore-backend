"""
Serializers pour l'application authentication - GESTORE
Gestion complète des utilisateurs, rôles et sécurité avec optimisations
"""
from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.db import transaction
from apps.core.serializers import (
    BaseModelSerializer, AuditableSerializer, NamedModelSerializer, 
    ActivableModelSerializer
)
from .models import Role, UserProfile, UserSession, UserAuditLog

User = get_user_model()


class RoleSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer):
    """
    Serializer pour les rôles avec permissions détaillées
    """
    role_type = serializers.CharField()
    
    # Permissions modules (conversion boolean -> string pour cohérence)
    can_manage_users = serializers.BooleanField()
    can_manage_inventory = serializers.BooleanField()
    can_manage_sales = serializers.BooleanField()
    can_manage_suppliers = serializers.BooleanField()
    can_view_reports = serializers.BooleanField()
    can_manage_reports = serializers.BooleanField()
    can_manage_settings = serializers.BooleanField()
    
    # Permissions financières
    can_apply_discounts = serializers.BooleanField()
    max_discount_percent = serializers.FloatField()
    can_void_transactions = serializers.BooleanField()
    
    # Champs calculés
    permissions_summary = serializers.SerializerMethodField()
    users_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Role
        fields = [
            'id', 'name', 'description', 'role_type', 'is_active',
            'can_manage_users', 'can_manage_inventory', 'can_manage_sales',
            'can_manage_suppliers', 'can_view_reports', 'can_manage_reports',
            'can_manage_settings', 'can_apply_discounts', 'max_discount_percent',
            'can_void_transactions', 'permissions_summary', 'users_count',
            'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
        
    def get_permissions_summary(self, obj):
        """
        Résumé textuel des permissions pour l'interface
        """
        permissions = []
        
        if obj.can_manage_users:
            permissions.append("Gestion utilisateurs")
        if obj.can_manage_inventory:
            permissions.append("Gestion stocks")
        if obj.can_manage_sales:
            permissions.append("Gestion ventes")
        if obj.can_manage_suppliers:
            permissions.append("Gestion fournisseurs")
        if obj.can_view_reports:
            permissions.append("Consultation rapports")
        if obj.can_manage_reports:
            permissions.append("Gestion rapports")
        if obj.can_manage_settings:
            permissions.append("Gestion paramètres")
        
        return permissions
    
    def get_users_count(self, obj):
        """
        Nombre d'utilisateurs assignés à ce rôle
        """
        return obj.user_set.filter(is_active=True).count()
    
    def validate_max_discount_percent(self, value):
        """
        Validation du pourcentage de remise maximum
        """
        if value < 0 or value > 100:
            raise serializers.ValidationError(
                "Le pourcentage de remise doit être entre 0 et 100."
            )
        return value
    
    def validate(self, attrs):
        """
        Validation globale du rôle
        """
        # Si peut appliquer des remises, doit avoir une limite définie
        if attrs.get('can_apply_discounts') and not attrs.get('max_discount_percent'):
            raise serializers.ValidationError({
                'max_discount_percent': 
                "Une limite de remise doit être définie si l'application de remises est autorisée."
            })
        
        # Validation des combinaisons de permissions logiques
        if attrs.get('can_manage_reports') and not attrs.get('can_view_reports'):
            attrs['can_view_reports'] = True  # Auto-correction
            
        return attrs


class UserProfileSerializer(BaseModelSerializer):
    """
    Serializer pour le profil utilisateur étendu
    """
    user_id = serializers.CharField(source='user.id', read_only=True)
    
    # Informations personnelles
    birth_date = serializers.DateField(allow_null=True, required=False)
    
    # Préférences interface
    language = serializers.CharField(default='fr')
    timezone = serializers.CharField(default='UTC')
    theme = serializers.CharField(default='light')
    
    # Notifications
    email_notifications = serializers.BooleanField(default=True)
    sms_notifications = serializers.BooleanField(default=False)
    
    # Statistiques (read-only)
    last_login_ip = serializers.IPAddressField(read_only=True)
    login_count = serializers.IntegerField(read_only=True)
    
    # Avatar avec URL complète
    avatar_url = serializers.SerializerMethodField()
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'user_id', 'avatar', 'avatar_url', 'birth_date', 
            'address', 'emergency_contact', 'emergency_phone',
            'language', 'timezone', 'theme', 'email_notifications',
            'sms_notifications', 'last_login_ip', 'login_count',
            'created_at', 'updated_at'
        ]
        
    def get_avatar_url(self, obj):
        """
        URL complète de l'avatar
        """
        if obj.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.avatar.url)
        return None
    
    def validate_language(self, value):
        """
        Validation de la langue
        """
        allowed_languages = ['fr', 'en']
        if value not in allowed_languages:
            raise serializers.ValidationError(
                f"Langue non supportée. Langues autorisées : {', '.join(allowed_languages)}"
            )
        return value
    
    def validate_theme(self, value):
        """
        Validation du thème
        """
        allowed_themes = ['light', 'dark', 'auto']
        if value not in allowed_themes:
            raise serializers.ValidationError(
                f"Thème non supporté. Thèmes autorisés : {', '.join(allowed_themes)}"
            )
        return value


class UserSessionSerializer(BaseModelSerializer):
    """
    Serializer pour les sessions utilisateur
    """
    user_id = serializers.CharField(source='user.id', read_only=True)
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    
    # Durée de session calculée
    session_duration = serializers.SerializerMethodField()
    is_current_session = serializers.SerializerMethodField()
    
    # Informations géographiques de l'IP (optionnel)
    ip_location = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user_id', 'user_name', 'session_key', 'ip_address',
            'user_agent', 'login_at', 'logout_at', 'is_active',
            'session_duration', 'is_current_session', 'ip_location'
        ]
        
    def get_session_duration(self, obj):
        """
        Durée de la session en secondes
        """
        if obj.logout_at:
            return int((obj.logout_at - obj.login_at).total_seconds())
        else:
            return int((timezone.now() - obj.login_at).total_seconds())
    
    def get_is_current_session(self, obj):
        """
        Indique si c'est la session actuelle
        """
        request = self.context.get('request')
        if request and hasattr(request, 'session'):
            return request.session.session_key == obj.session_key
        return False
    
    def get_ip_location(self, obj):
        """
        Localisation approximative de l'IP (pour info)
        """
        # TODO: Intégrer un service de géolocalisation IP si nécessaire
        # Pour l'instant, on retourne juste le type d'IP
        import ipaddress
        try:
            ip = ipaddress.ip_address(obj.ip_address)
            if ip.is_private:
                return "Réseau local"
            elif ip.is_loopback:
                return "Localhost"
            else:
                return "Internet"
        except:
            return "Inconnue"


class UserSerializer(AuditableSerializer, ActivableModelSerializer):
    """
    Serializer principal pour les utilisateurs avec optimisations
    """
    # Informations de base
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=30, allow_blank=True)
    last_name = serializers.CharField(max_length=30, allow_blank=True)
    
    # Informations professionnelles
    employee_code = serializers.CharField(read_only=True)
    phone_number = serializers.CharField(allow_blank=True, required=False)
    hire_date = serializers.DateField(allow_null=True, required=False)
    department = serializers.CharField(allow_blank=True, required=False)
    
    # Rôle avec expansion
    role = RoleSerializer(read_only=True)
    role_id = serializers.CharField(write_only=True, allow_null=True, required=False)
    
    # Profil avec expansion conditionnelle
    profile = UserProfileSerializer(read_only=True)
    
    # Sécurité (read-only)
    is_locked = serializers.BooleanField(read_only=True)
    locked_until = serializers.DateTimeField(read_only=True)
    failed_login_attempts = serializers.IntegerField(read_only=True)
    last_password_change = serializers.DateTimeField(read_only=True)
    
    # Champs calculés
    full_name = serializers.SerializerMethodField()
    is_online = serializers.SerializerMethodField()
    permissions_summary = serializers.SerializerMethodField()
    last_login_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'employee_code', 'phone_number', 'hire_date', 'department',
            'role', 'role_id', 'profile', 'is_active', 'is_locked', 'locked_until',
            'failed_login_attempts', 'last_login', 'last_login_formatted',
            'last_password_change', 'is_online', 'permissions_summary',
            'created_at', 'updated_at', 'created_by', 'updated_by'
        ]
        
    def get_full_name(self, obj):
        """
        Nom complet de l'utilisateur
        """
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username
    
    def get_is_online(self, obj):
        """
        Indique si l'utilisateur est actuellement en ligne
        """
        # Considérer en ligne si session active dans les 15 dernières minutes
        cutoff = timezone.now() - timezone.timedelta(minutes=15)
        return obj.usersession.filter(
            is_active=True,
            login_at__gte=cutoff
        ).exists()
    
    def get_permissions_summary(self, obj):
        """
        Résumé des permissions pour l'interface
        """
        if obj.is_superuser:
            return ["Administrateur système (tous droits)"]
        
        if obj.role:
            return obj.role.permissions_summary if hasattr(obj.role, 'permissions_summary') else []
        
        return []
    
    def get_last_login_formatted(self, obj):
        """
        Dernière connexion formatée pour l'interface
        """
        if obj.last_login:
            return obj.last_login.strftime('%d/%m/%Y à %H:%M')
        return "Jamais connecté"
    
    def validate_email(self, value):
        """
        Validation de l'email avec vérification d'unicité
        """
        if not value:
            raise serializers.ValidationError("L'email est obligatoire.")
        
        # Vérifier l'unicité (exclure l'instance actuelle en cas de modification)
        queryset = User.objects.filter(email__iexact=value)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        
        if queryset.exists():
            raise serializers.ValidationError("Un utilisateur avec cet email existe déjà.")
        
        return value.lower()
    
    def validate_username(self, value):
        """
        Validation du nom d'utilisateur
        """
        if not value:
            raise serializers.ValidationError("Le nom d'utilisateur est obligatoire.")
        
        # Vérifier l'unicité
        queryset = User.objects.filter(username__iexact=value)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        
        if queryset.exists():
            raise serializers.ValidationError("Ce nom d'utilisateur est déjà pris.")
        
        return value
    
    def validate_role_id(self, value):
        """
        Validation du rôle assigné
        """
        if value:
            try:
                role = Role.objects.get(id=value, is_active=True)
                
                # Vérifier les permissions pour assigner ce rôle
                request = self.context.get('request')
                if request and request.user:
                    if not request.user.is_superuser:
                        # Seuls les admins peuvent assigner le rôle admin
                        if role.role_type == 'admin':
                            raise serializers.ValidationError(
                                "Seul un administrateur système peut assigner le rôle d'administrateur."
                            )
                        
                        # Vérifier que l'utilisateur a le droit de gérer les utilisateurs
                        if not (request.user.role and request.user.role.can_manage_users):
                            raise serializers.ValidationError(
                                "Vous n'avez pas le droit d'assigner des rôles."
                            )
                
                return value
                
            except Role.DoesNotExist:
                raise serializers.ValidationError("Rôle non trouvé ou inactif.")
        
        return value
    
    def validate_phone_number(self, value):
        """
        Validation du numéro de téléphone
        """
        if value:
            import re
            # Format international basique
            if not re.match(r'^\+?[1-9]\d{1,14}$', value.replace(' ', '').replace('-', '')):
                raise serializers.ValidationError(
                    "Format de téléphone invalide. Utilisez le format international."
                )
        
        return value
    
    def validate(self, attrs):
        """
        Validation globale de l'utilisateur
        """
        # Si c'est une création, s'assurer qu'un rôle est assigné
        if not self.instance and not attrs.get('role_id'):
            # Assigner le rôle par défaut (caissier)
            try:
                default_role = Role.objects.get(role_type='cashier', is_active=True)
                attrs['role_id'] = str(default_role.id)
            except Role.DoesNotExist:
                raise serializers.ValidationError({
                    'role_id': "Aucun rôle par défaut trouvé. Veuillez assigner un rôle."
                })
        
        return attrs
    
    def create(self, validated_data):
        """
        Création d'utilisateur avec profil automatique
        """
        role_id = validated_data.pop('role_id', None)
        
        with transaction.atomic():
            # Créer l'utilisateur
            user = User.objects.create_user(**validated_data)
            
            # Assigner le rôle
            if role_id:
                try:
                    role = Role.objects.get(id=role_id)
                    user.role = role
                    user.save()
                except Role.DoesNotExist:
                    pass
            
            # Créer le profil automatiquement
            UserProfile.objects.create(user=user)
            
            return user
    
    def update(self, instance, validated_data):
        """
        Mise à jour d'utilisateur avec gestion du rôle
        """
        role_id = validated_data.pop('role_id', None)
        
        with transaction.atomic():
            # Mettre à jour les champs de base
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            
            # Mettre à jour le rôle si fourni
            if role_id is not None:
                try:
                    if role_id:
                        role = Role.objects.get(id=role_id)
                        instance.role = role
                    else:
                        instance.role = None
                except Role.DoesNotExist:
                    pass
            
            instance.save()
            return instance


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer spécialisé pour la création d'utilisateur avec mot de passe
    """
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, style={'input_type': 'password'})
    
    role_id = serializers.CharField(required=False, allow_null=True)
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name', 'phone_number',
            'hire_date', 'department', 'role_id', 'password', 'password_confirm'
        ]
    
    def validate_password(self, value):
        """
        Validation du mot de passe avec les règles Django
        """
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        
        return value
    
    def validate(self, attrs):
        """
        Validation des mots de passe correspondants
        """
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        
        if password != password_confirm:
            raise serializers.ValidationError({
                'password_confirm': "Les mots de passe ne correspondent pas."
            })
        
        return attrs
    
    def create(self, validated_data):
        """
        Création avec mot de passe hashé
        """
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        role_id = validated_data.pop('role_id', None)
        
        with transaction.atomic():
            # Créer l'utilisateur
            user = User.objects.create_user(password=password, **validated_data)
            
            # Assigner le rôle
            if role_id:
                try:
                    role = Role.objects.get(id=role_id, is_active=True)
                    user.role = role
                    user.save()
                except Role.DoesNotExist:
                    pass
            
            # Créer le profil
            UserProfile.objects.create(user=user)
            
            return user


class UserListSerializer(BaseModelSerializer):
    """
    Serializer allégé pour les listes d'utilisateurs (optimisé)
    """
    full_name = serializers.SerializerMethodField()
    role_name = serializers.CharField(source='role.name', read_only=True)
    role_type = serializers.CharField(source='role.role_type', read_only=True)
    is_online = serializers.SerializerMethodField()
    last_login_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'full_name', 'employee_code',
            'role_name', 'role_type', 'is_active', 'is_locked', 
            'is_online', 'last_login_formatted'
        ]
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username
    
    def get_is_online(self, obj):
        # Version optimisée avec préfetch
        if hasattr(obj, '_is_online'):
            return obj._is_online
        return False
    
    def get_last_login_formatted(self, obj):
        if obj.last_login:
            return obj.last_login.strftime('%d/%m/%Y')
        return "Jamais"


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer pour le changement de mot de passe
    """
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate_current_password(self, value):
        """
        Validation du mot de passe actuel
        """
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Mot de passe actuel incorrect.")
        
        return value
    
    def validate_new_password(self, value):
        """
        Validation du nouveau mot de passe
        """
        try:
            validate_password(value, user=self.context['request'].user)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        
        return value
    
    def validate(self, attrs):
        """
        Validation que les nouveaux mots de passe correspondent
        """
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': "Les nouveaux mots de passe ne correspondent pas."
            })
        
        return attrs
    
    def save(self):
        """
        Sauvegarde du nouveau mot de passe
        """
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.last_password_change = timezone.now()
        user.save()
        
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializer pour l'authentification
    """
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    remember_me = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        """
        Validation des credentials et authentification
        """
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            # Tentative d'authentification
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )
            
            if not user:
                raise serializers.ValidationError(
                    "Nom d'utilisateur ou mot de passe incorrect."
                )
            
            if not user.is_active:
                raise serializers.ValidationError(
                    "Ce compte utilisateur est désactivé."
                )
            
            # Vérifier si le compte est verrouillé
            if user.is_account_locked():
                raise serializers.ValidationError(
                    f"Compte verrouillé jusqu'à {user.locked_until.strftime('%H:%M')}."
                )
            
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError(
                "Le nom d'utilisateur et le mot de passe sont requis."
            )


class UserAuditLogSerializer(BaseModelSerializer):
    """
    Serializer pour les logs d'audit utilisateur
    """
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = UserAuditLog
        fields = [
            'id', 'user_name', 'action', 'action_display', 'model_name',
            'object_id', 'object_repr', 'changes', 'ip_address',
            'user_agent', 'timestamp'
        ]