"""
Permissions spécifiques pour l'application sales - GESTORE
"""
from apps.core.permissions import RoleBasedPermission


class CanViewSales(RoleBasedPermission):
    """
    Permission : consultation des ventes
    """
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        # Lecture autorisée pour tous les utilisateurs authentifiés avec permissions sales
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return (
                hasattr(request.user, 'role') and 
                request.user.role and 
                request.user.role.can_manage_sales
            )
        
        # Modification selon les permissions
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_sales
        )


class CanManageSales(RoleBasedPermission):
    """
    Permission : gestion complète des ventes (managers/admins)
    """
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_sales and
            request.user.role.role_type in ['admin', 'manager']
        )


class CanVoidTransaction(RoleBasedPermission):
    """
    Permission : annulation de transactions
    Réservé aux managers et admins
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
        if not super().has_object_permission(request, view, obj):
            return False
        
        if request.user.is_superuser:
            return True
        
        # Vérifier le pourcentage de remise maximum autorisé
        if hasattr(obj, 'discount_percentage'):
            max_discount = request.user.role.max_discount_percent or 0
            if obj.discount_percentage > max_discount:
                return False
        
        return True


class CanManageCustomers(RoleBasedPermission):
    """
    Permission : gestion des clients
    """
    def has_permission(self, request, view):
        # Ne pas appeler super() pour éviter le conflit avec RoleBasedPermission
        # Vérifier d'abord l'authentification de base
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True
        
        # Lecture autorisée pour tous avec permission sales
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return (
                hasattr(request.user, 'role') and 
                request.user.role and 
                request.user.role.can_manage_sales
            )
        
        # Création/modification selon role
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_sales
        )