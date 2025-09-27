"""
Serializers de base pour l'application core - GESTORE
Ces serializers abstraits sont utilisés par toutes les autres applications
"""
from rest_framework import serializers


class TimestampedSerializer(serializers.ModelSerializer):
    """
    Serializer de base pour les modèles avec timestamps
    Formatage cohérent des dates pour le frontend
    """
    created_at = serializers.DateTimeField(
        format='%Y-%m-%d %H:%M:%S',
        read_only=True
    )
    updated_at = serializers.DateTimeField(
        format='%Y-%m-%d %H:%M:%S', 
        read_only=True
    )
    
    class Meta:
        abstract = True


class UUIDSerializer(serializers.ModelSerializer):
    """
    Serializer de base pour les modèles avec UUID
    Force l'ID en string pour uniformité frontend
    """
    id = serializers.CharField(read_only=True)
    
    class Meta:
        abstract = True


class SoftDeleteSerializer(serializers.ModelSerializer):
    """
    Serializer de base pour la suppression logique
    Gère les champs de suppression logique
    """
    is_deleted = serializers.BooleanField(read_only=True)
    deleted_at = serializers.DateTimeField(
        format='%Y-%m-%d %H:%M:%S',
        read_only=True
    )
    
    class Meta:
        abstract = True


class SyncStatusSerializer(serializers.ModelSerializer):
    """
    Serializer de base pour la synchronisation
    Gère les informations de sync pour le frontend
    """
    sync_status = serializers.CharField(read_only=True)
    last_sync_at = serializers.DateTimeField(
        format='%Y-%m-%d %H:%M:%S',
        read_only=True
    )
    
    # Champ calculé pour indiquer si l'objet nécessite une sync
    needs_sync = serializers.SerializerMethodField()
    
    def get_needs_sync(self, obj):
        """Indique si l'objet a besoin d'être synchronisé"""
        return obj.sync_status in ['pending', 'conflict', 'error']
    
    class Meta:
        abstract = True


class BaseModelSerializer(UUIDSerializer, TimestampedSerializer, 
                         SoftDeleteSerializer, SyncStatusSerializer):
    """
    Serializer de base principal combinant tous les comportements
    Utilisé par la plupart des serializers métier
    """
    class Meta:
        abstract = True
        
    def to_representation(self, instance):
        """
        Personnalise la représentation pour le frontend
        """
        data = super().to_representation(instance)
        
        # Ajouter des métadonnées utiles pour le frontend
        if hasattr(instance, '_meta'):
            data['_meta'] = {
                'model_name': instance._meta.model_name,
                'verbose_name': str(instance._meta.verbose_name),
                'app_label': instance._meta.app_label,
            }
        
        return data


class AuditableSerializer(BaseModelSerializer):
    """
    Serializer pour les modèles avec audit trail
    Inclut les informations de création/modification par utilisateur
    """
    created_by = serializers.StringRelatedField(read_only=True)
    updated_by = serializers.StringRelatedField(read_only=True)
    created_by_id = serializers.CharField(source='created_by.id', read_only=True)
    updated_by_id = serializers.CharField(source='updated_by.id', read_only=True)
    
    class Meta:
        abstract = True


class NamedModelSerializer(serializers.ModelSerializer):
    """
    Serializer pour les entités avec nom/désignation
    """
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(allow_blank=True, required=False)
    
    def validate_name(self, value):
        """
        Validation du nom : pas vide, pas que des espaces
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Le nom ne peut pas être vide.")
        
        return value.strip()
    
    class Meta:
        abstract = True


class CodedModelSerializer(serializers.ModelSerializer):
    """
    Serializer pour les entités avec code unique
    """
    code = serializers.CharField(max_length=50)
    
    def validate_code(self, value):
        """
        Validation du code : format, unicité
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Le code ne peut pas être vide.")
        
        # Nettoyer le code (supprimer espaces, convertir en majuscules)
        cleaned_code = value.strip().upper()
        
        # Vérifier le format (alphanumérique + tirets/underscores)
        import re
        if not re.match(r'^[A-Z0-9_-]+$', cleaned_code):
            raise serializers.ValidationError(
                "Le code ne peut contenir que des lettres, chiffres, tirets et underscores."
            )
        
        return cleaned_code
    
    class Meta:
        abstract = True


class ActivableModelSerializer(serializers.ModelSerializer):
    """
    Serializer pour les entités activables/désactivables
    """
    is_active = serializers.BooleanField(default=True)
    
    # Champ calculé pour le statut textuel
    status_display = serializers.SerializerMethodField()
    
    def get_status_display(self, obj):
        """Retourne le statut sous forme textuelle"""
        return "Actif" if obj.is_active else "Inactif"
    
    class Meta:
        abstract = True


class PricedModelSerializer(serializers.ModelSerializer):
    """
    Serializer pour les entités avec prix
    Conversion Decimal -> float pour le frontend
    """
    price = serializers.FloatField()
    
    def validate_price(self, value):
        """
        Validation du prix : positif ou nul
        """
        if value < 0:
            raise serializers.ValidationError("Le prix ne peut pas être négatif.")
        
        return value
    
    class Meta:
        abstract = True


class OrderedModelSerializer(serializers.ModelSerializer):
    """
    Serializer pour les entités ordonnables
    """
    order = serializers.IntegerField(default=0)
    
    def validate_order(self, value):
        """
        Validation de l'ordre : entier positif
        """
        if value < 0:
            raise serializers.ValidationError("L'ordre ne peut pas être négatif.")
        
        return value
    
    class Meta:
        abstract = True


class BulkOperationSerializer(serializers.Serializer):
    """
    Serializer pour les opérations en masse
    """
    action = serializers.ChoiceField(choices=[
        ('activate', 'Activer'),
        ('deactivate', 'Désactiver'),
        ('delete', 'Supprimer'),
        ('update', 'Modifier'),
    ])
    ids = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False
    )
    data = serializers.DictField(required=False, allow_empty=True)
    
    def validate_ids(self, value):
        """
        Validation de la liste d'IDs
        """
        if not value:
            raise serializers.ValidationError("La liste d'IDs ne peut pas être vide.")
        
        if len(value) > 1000:
            raise serializers.ValidationError("Maximum 1000 éléments par opération en masse.")
        
        return value


class ValidationErrorSerializer(serializers.Serializer):
    """
    Serializer pour standardiser les erreurs de validation
    """
    field = serializers.CharField()
    message = serializers.CharField()
    code = serializers.CharField()


class APIResponseSerializer(serializers.Serializer):
    """
    Serializer pour standardiser les réponses API
    """
    success = serializers.BooleanField()
    message = serializers.CharField(allow_blank=True)
    data = serializers.DictField(allow_empty=True)
    errors = ValidationErrorSerializer(many=True, required=False)
    meta = serializers.DictField(allow_empty=True, required=False)


class SearchFilterSerializer(serializers.Serializer):
    """
    Serializer pour les filtres de recherche
    """
    q = serializers.CharField(
        required=False, 
        allow_blank=True,
        help_text="Terme de recherche général"
    )
    ordering = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Champ de tri (préfixer par - pour décroissant)"
    )
    limit = serializers.IntegerField(
        required=False,
        min_value=1,
        max_value=1000,
        default=50,
        help_text="Nombre d'éléments par page"
    )
    offset = serializers.IntegerField(
        required=False,
        min_value=0,
        default=0,
        help_text="Décalage pour la pagination"
    )
    
    def validate_ordering(self, value):
        """
        Validation du champ de tri
        """
        if not value:
            return value
        
        # Nettoyer et valider les champs de tri
        allowed_fields = getattr(self.context.get('view'), 'ordering_fields', [])
        if allowed_fields:
            clean_field = value.lstrip('-')
            if clean_field not in allowed_fields:
                raise serializers.ValidationError(
                    f"Tri non autorisé sur le champ '{clean_field}'. "
                    f"Champs autorisés : {', '.join(allowed_fields)}"
                )
        
        return value