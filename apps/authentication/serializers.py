"""
Serializers pour l'application authentication - GESTORE
Gestion complète des utilisateurs, rôles et sécurité avec optimisations - VERSION CORRIGÉE
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
        # CORRIGÉ: obj.user_set -> obj.users (relation définie dans migration 0002)
        return obj.users.filter(is_active=True).count()
    
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
        
        return attrs


class UserProfileSerializer(BaseModelSerializer):
    """
    Serializer pour les profils utilisateur
    """
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    avatar_url = serializers.SerializerMethodField()
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'user_name', 'avatar', 'avatar_url', 'birth_date', 
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
            return obj.avatar.url
        return None


class UserSessionSerializer(BaseModelSerializer):
    """
    Serializer pour les sessions utilisateur
    """
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    duration = serializers.SerializerMethodField()
    location = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user_name', 'session_key', 'ip_address', 'user_agent',
            'login_at', 'logout_at', 'is_active', 'duration', 'location'
        ]
    
    def get_duration(self, obj):
        """
        Durée de la session
        """
        if obj.logout_at:
            duration = obj.logout_at - obj.login_at
        else:
            duration = timezone.now() - obj.login_at
        
        total_seconds = int(duration.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def get_location(self, obj):
        """
        Localisation approximative de l'IP
        """
        try:
            from ipaddress import ip_address
            ip = ip_address(obj.ip_address)
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
        # CORRIGÉ: obj.usersession -> obj.sessions (relation définie dans migration 0002)
        return obj.sessions.filter(
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


class UserCreateSerializer(BaseModelSerializer):
    """
    Serializer pour la création d'utilisateur avec mot de passe - VERSION CORRIGÉE
    """
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    # ✅ CORRECTION : Ajouter required=False pour rendre optionnels
    first_name = serializers.CharField(max_length=30, allow_blank=True, required=False)
    last_name = serializers.CharField(max_length=30, allow_blank=True, required=False)
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    role_id = serializers.CharField(write_only=True, allow_null=True, required=False)
    
    # Informations professionnelles
    phone_number = serializers.CharField(allow_blank=True, required=False)
    hire_date = serializers.DateField(allow_null=True, required=False)
    department = serializers.CharField(allow_blank=True, required=False)
    
    class Meta:
        model = User
        fields = [
            # ✅ CORRECTION : Ajouter 'id' pour l'inclure dans la réponse
            'id', 'username', 'email', 'first_name', 'last_name', 
            'password', 'password_confirm', 'role_id',
            'phone_number', 'hire_date', 'department'
        ]
    
    def validate_email(self, value):
        """
        Validation de l'email avec vérification d'unicité
        """
        if not value:
            raise serializers.ValidationError("L'email est obligatoire.")
        
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Un utilisateur avec cet email existe déjà.")
        
        return value.lower()
    
    def validate_username(self, value):
        """
        Validation du nom d'utilisateur
        """
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("Ce nom d'utilisateur est déjà pris.")
        
        return value
    
    def validate_password(self, value):
        """
        Validation de la force du mot de passe
        """
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.messages)
        
        return value
    
    def validate(self, attrs):
        """
        Validation globale avec vérification de la confirmation du mot de passe
        """
        errors = {}
        
        # Vérification de la confirmation du mot de passe
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        
        if password and password_confirm:
            if password != password_confirm:
                errors['password_confirm'] = "Les mots de passe ne correspondent pas."
        elif password and not password_confirm:
            errors['password_confirm'] = "La confirmation du mot de passe est obligatoire."
        elif not password and password_confirm:
            errors['password'] = "Le mot de passe est obligatoire."
        
        # Validation du rôle si fourni
        role_id = attrs.get('role_id')
        if role_id:
            try:
                role = Role.objects.get(id=role_id, is_active=True)
                attrs['role'] = role
            except Role.DoesNotExist:
                errors['role_id'] = "Rôle non trouvé ou inactif."
        
        # Lever toutes les erreurs trouvées
        if errors:
            raise serializers.ValidationError(errors)
        
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
            
            # Créer le profil SEULEMENT s'il n'existe pas
            if not hasattr(user, 'profile'):
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
        """
        Version optimisée avec préfetch - CORRIGÉ CombinedExpression
        """
        # CORRECTION CRITIQUE : Count retourne un nombre, pas un booléen
        if hasattr(obj, '_is_online'):
            return obj._is_online > 0  # FIXED: Conversion en booléen
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
            validate_password(value, self.context['request'].user)
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.messages)
        
        return value
    
    def validate(self, attrs):
        """
        Validation globale
        """
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'Les nouveaux mots de passe ne correspondent pas.'
            })
        
        return attrs
    
    def save(self):
        """
        Enregistrer le nouveau mot de passe
        """
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializer pour la connexion utilisateur
    """
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """
        Validation des identifiants
        """
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
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
                    "Ce compte est désactivé."
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