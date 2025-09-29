"""
Permissions spécifiques pour l'application inventory - GESTORE
"""
from apps.core.permissions import RoleBasedPermission


class CanViewInventory(RoleBasedPermission):
    """
    Permission : consultation des stocks
    """
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        # Lecture autorisée pour tous les utilisateurs authentifiés
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Modification selon les permissions
        if request.user.is_superuser:
            return True
        
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            (request.user.role.can_manage_inventory or request.user.role.can_manage_sales)
        )


class CanModifyPrices(RoleBasedPermission):
    """
    Permission : modification des prix
    """
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        # Seuls les managers peuvent modifier les prix
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.role_type in ['admin', 'manager'] and
            request.user.role.can_manage_inventory
        )


class CanManageStockMovements(RoleBasedPermission):
    """
    Permission : gestion des mouvements de stock
    """
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        # Lecture autorisée pour tous
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return (
                hasattr(request.user, 'role') and 
                request.user.role and 
                (request.user.role.can_manage_inventory or request.user.role.can_manage_sales)
            )
        
        # Création/modification selon permissions
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.can_manage_inventory
        )


class CanAdjustStock(RoleBasedPermission):
    """
    Permission : ajustement de stock (inventaire)
    """
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        if request.user.is_superuser:
            return True
        
        # Ajustements réservés aux managers et admins
        return (
            hasattr(request.user, 'role') and 
            request.user.role and 
            request.user.role.role_type in ['admin', 'manager'] and
            request.user.role.can_manage_inventory
        )