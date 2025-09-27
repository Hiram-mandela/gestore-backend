"""
Permissions personnalisées pour GESTORE
Système de permissions granulaires basé sur les rôles
"""
from rest_framework import permissions
from django.contrib.auth import get_user_model

User = get_user_model()


class BaseGestorePermission(permissions.BasePermission):
    """
    Permission de base pour GESTORE
    Vérifie que l'utilisateur est authentifié et actif
    """
    
    def has_permission(self, request, view):
        """
        Permission au niveau de la vue
        """
        # Utilisateur doit être authentifié
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Utilisateur doit être actif
        if not request.user.is_active:
            return False
            
        # Vérifier que le compte n'est pas verrouillé
        if hasattr(request.user, 'is_account_locked') and request.user.is_account_locked():
            return False
        
        return True
    
    def has_object_permission(self, request, view, obj):
        """
        Permission au niveau de l'objet
        """
        return self.has_permission(request, view)


class IsOwnerOrReadOnly(BaseGestorePermission):
    """
    Permission : propriétaire peut modifier, autres en lecture seule
    """
    
    def has_object_permission(self, request, view, obj):
        # Permissions de lecture pour tous
        if request.method in permissions.SAFE_METHODS:
            return super().has_permission(request, view)
        
        # Permissions d'écriture seulement pour le propriétaire
        if hasattr(obj, 'created_by'):
            return obj.created_by == request.user
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user
        
        return False


class IsSuperUserOrReadOnly(BaseGestorePermission):
    """
    Permission : admin peut tout, autres en lecture seule
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        # Lecture autorisée pour tous
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Écriture seulement pour les super utilisateurs
        return request.user.is_superuser


class RoleBasedPermission(BaseGestorePermission):
    """
    Permission basée sur les rôles GESTORE
    Vérification dynamique des permissions selon le rôle
    """
    
    # Mapping des actions vers les permissions requises
    PERMISSION_MAPPING = {
        'list': None,  # Lecture autorisée par défaut
        'retrieve': None,  # Lecture autorisée par défaut
        'create': 'can_create',
        'update': 'can_update', 
        'partial_update': 'can_update',
        'destroy': 'can_delete',
    }
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        # Récupérer l'action de la vue
        action = getattr(view, 'action', None)
        
        # Vérifier la permission requise pour cette action
        required_permission = self.PERMISSION_MAPPING.get(action)
        
        if required_permission is None:
            return True  # Pas de permission spécifique requise
        
        # Vérifier si l'utilisateur a la permission
        return self.user_has_permission(request.user, required_permission, view)
    
    def user_has_permission(self, user, permission, view):
        """
        Vérifie si l'utilisateur a la permission spécifiée
        """
        if user.is_superuser:
            return True
        
        if not hasattr(user, 'role') or not user.role:
            return False
        
        # Vérifier les permissions Django standard
        app_label = getattr(view, 'queryset', None)
        if app_label and hasattr(app_label, 'model'):
            model = app_label.model
            perm_code = f"{model._meta.app_label}.{permission}_{model._meta.model_name}"
            if user.has_perm(perm_code):
                return True
        
        # Vérifier les permissions personnalisées du rôle
        role = user.role
        return getattr(role, permission, False)


class CanManageUsers(RoleBasedPermission):
    """
    Permission : gestion des utilisateurs
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_users
        )


class CanManageInventory(RoleBasedPermission):
    """
    Permission : gestion des stocks
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_inventory
        )


class CanManageSales(RoleBasedPermission):
    """
    Permission : gestion des ventes
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_sales
        )


class CanApplyDiscounts(RoleBasedPermission):
    """
    Permission : application de remises
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_apply_discounts
        )
    
    def has_object_permission(self, request, view, obj):
        """
        Vérifier les limites de remise selon le rôle
        """
        if not self.has_permission(request, view):
            return False
        
        # Pour les remises, vérifier le pourcentage maximum autorisé
        if hasattr(obj, 'percentage_value') and obj.percentage_value:
            max_discount = request.user.role.max_discount_percent
            return obj.percentage_value <= max_discount
        
        return True


class CanVoidTransactions(RoleBasedPermission):
    """
    Permission : annulation de transactions
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_void_transactions
        )


class CanManageSuppliers(RoleBasedPermission):
    """
    Permission : gestion des fournisseurs
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_suppliers
        )


class CanViewReports(RoleBasedPermission):
    """
    Permission : consultation des rapports
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_view_reports
        )


class CanManageReports(RoleBasedPermission):
    """
    Permission : gestion des rapports
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_reports
        )


class CanManageSettings(RoleBasedPermission):
    """
    Permission : gestion des paramètres système
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_settings
        )


class CanManageSync(RoleBasedPermission):
    """
    Permission : gestion de la synchronisation
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        # Synchronisation limitée aux administrateurs système
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.role_type == 'admin'
        )


class SystemSyncPermission(permissions.BasePermission):
    """
    Permission spéciale pour la synchronisation automatique
    Utilisée par les nœuds de synchronisation
    """
    
    def has_permission(self, request, view):
        # Vérifier la clé API de synchronisation
        api_key = request.META.get('HTTP_X_SYNC_API_KEY')
        if not api_key:
            return False
        
        # Vérifier que la clé API est valide
        from apps.sync.models import SyncNode
        try:
            node = SyncNode.objects.get(api_key=api_key, status='active')
            # Ajouter le nœud au contexte de la requête
            request.sync_node = node
            return True
        except SyncNode.DoesNotExist:
            return False


class LicenseValidationPermission(permissions.BasePermission):
    """
    Permission pour la validation de licence
    Utilisée par le système de licence
    """
    
    def has_permission(self, request, view):
        # Validation automatique de licence - toujours autorisée
        # La validation réelle se fait dans la vue
        return True


class LocationBasedPermission(BaseGestorePermission):
    """
    Permission basée sur l'emplacement (pour les magasins multi-sites)
    """
    
    def has_object_permission(self, request, view, obj):
        if not super().has_object_permission(request, view, obj):
            return False
        
        # Si l'objet a un emplacement, vérifier l'accès
        if hasattr(obj, 'location') and obj.location:
            # TODO: Implémenter la logique d'accès par emplacement
            # pour la version multi-sites
            pass
        
        return True


class TimeBasedPermission(BaseGestorePermission):
    """
    Permission basée sur les horaires (pour les actions sensibles)
    """
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        # Vérifier les heures d'ouverture pour certaines actions
        action = getattr(view, 'action', None)
        
        # Actions sensibles limitées aux heures d'ouverture
        sensitive_actions = ['destroy', 'void_transaction', 'bulk_delete']
        
        if action in sensitive_actions:
            from django.utils import timezone
            now = timezone.now()
            
            # Exemple : limiter les suppressions entre 8h et 20h
            if not (8 <= now.hour <= 20):
                return False
        
        return True


class IPWhitelistPermission(permissions.BasePermission):
    """
    Permission basée sur la liste blanche d'adresses IP
    Pour les actions critiques
    """
    
    ALLOWED_IPS = [
        '127.0.0.1',  # Localhost
        '::1',        # IPv6 localhost
        # Ajouter d'autres IPs autorisées selon la configuration
    ]
    
    def has_permission(self, request, view):
        # Récupérer l'IP du client
        ip_address = self.get_client_ip(request)
        
        # Vérifier si l'IP est dans la liste blanche
        return ip_address in self.ALLOWED_IPS
    
    def get_client_ip(self, request):
        """
        Récupère l'adresse IP réelle du client
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip