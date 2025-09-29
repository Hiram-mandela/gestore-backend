"""
Serializers pour l'application sales - GESTORE
Gestion complète des ventes, clients et paiements avec optimisations
"""
from rest_framework import serializers
from django.db.models import Sum, Count, Q, F
from django.utils import timezone
from decimal import Decimal

from apps.core.serializers import (
    BaseModelSerializer, AuditableSerializer, NamedModelSerializer,
    ActivableModelSerializer, BulkOperationSerializer
)
from .models import (
    Customer, PaymentMethod, Sale, SaleItem, Payment,
    Discount, SaleDiscount, Receipt
)
from apps.inventory.serializers import ArticleListSerializer


# ========================
# CLIENTS
# ========================

class CustomerSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer):
    """
    Serializer pour les clients
    """
    customer_type = serializers.ChoiceField(choices=[
        ('individual', 'Particulier'),
        ('company', 'Entreprise'),
        ('professional', 'Professionnel'),
    ])
    
    customer_code = serializers.CharField(read_only=True)
    
    # Informations de contact
    first_name = serializers.CharField(max_length=50, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=50, required=False, allow_blank=True)
    company_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)
    address = serializers.CharField(required=False, allow_blank=True)
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    postal_code = serializers.CharField(max_length=10, required=False, allow_blank=True)
    country = serializers.CharField(max_length=50, default='Côte d\'Ivoire')
    tax_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    
    # Fidélité
    loyalty_card_number = serializers.CharField(max_length=20, required=False, allow_null=True)
    loyalty_points = serializers.IntegerField(default=0, read_only=True)
    
    # Statistiques
    total_purchases = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)
    purchase_count = serializers.IntegerField(read_only=True)
    last_purchase_date = serializers.DateTimeField(read_only=True)
    
    # Préférences
    preferred_payment_method = serializers.CharField(max_length=20, required=False, allow_blank=True)
    marketing_consent = serializers.BooleanField(default=False)
    
    # Champs calculés
    full_name = serializers.SerializerMethodField()
    can_use_loyalty = serializers.SerializerMethodField()
    
    class Meta:
        model = Customer
        fields = [
            'id', 'name', 'description', 'customer_type', 'customer_code',
            'first_name', 'last_name', 'company_name', 'full_name',
            'email', 'phone', 'address', 'city', 'postal_code', 'country',
            'tax_number', 'loyalty_card_number', 'loyalty_points',
            'total_purchases', 'purchase_count', 'last_purchase_date',
            'preferred_payment_method', 'marketing_consent',
            'can_use_loyalty', 'is_active', 'status_display',
            'created_at', 'updated_at', 'sync_status', 'needs_sync'
        ]
    
    def get_full_name(self, obj):
        """Nom complet du client"""
        return obj.get_full_name()
    
    def get_can_use_loyalty(self, obj):
        """Peut utiliser des points de fidélité"""
        return obj.loyalty_points > 0
    
    def validate(self, attrs):
        """Validation des données client"""
        customer_type = attrs.get('customer_type')
        
        # Validation selon le type de client
        if customer_type == 'company' and not attrs.get('company_name'):
            raise serializers.ValidationError({
                'company_name': 'Le nom de l\'entreprise est requis pour un client entreprise.'
            })
        
        if customer_type == 'individual':
            if not attrs.get('first_name') and not attrs.get('last_name'):
                raise serializers.ValidationError({
                    'first_name': 'Le prénom ou le nom est requis pour un particulier.'
                })
        
        return attrs


class CustomerListSerializer(BaseModelSerializer):
    """
    Serializer optimisé pour les listes de clients
    """
    customer_code = serializers.CharField(read_only=True)
    full_name = serializers.SerializerMethodField()
    loyalty_points = serializers.IntegerField()
    total_purchases = serializers.DecimalField(max_digits=12, decimal_places=2)
    purchase_count = serializers.IntegerField()
    
    class Meta:
        model = Customer
        fields = [
            'id', 'customer_code', 'full_name', 'customer_type',
            'email', 'phone', 'loyalty_points', 'total_purchases',
            'purchase_count', 'last_purchase_date', 'is_active',
            'created_at'
        ]
    
    def get_full_name(self, obj):
        return obj.get_full_name()


# ========================
# MOYENS DE PAIEMENT
# ========================

class PaymentMethodSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer):
    """
    Serializer pour les moyens de paiement
    """
    payment_type = serializers.ChoiceField(choices=[
        ('cash', 'Espèces'),
        ('card', 'Carte bancaire'),
        ('mobile_money', 'Mobile Money'),
        ('check', 'Chèque'),
        ('credit', 'Crédit'),
        ('voucher', 'Bon d\'achat'),
        ('loyalty_points', 'Points fidélité'),
    ])
    
    requires_authorization = serializers.BooleanField(default=False)
    max_amount = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    fee_percentage = serializers.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    integration_config = serializers.JSONField(default=dict, required=False)
    
    class Meta:
        model = PaymentMethod
        fields = [
            'id', 'name', 'description', 'payment_type', 'requires_authorization',
            'max_amount', 'fee_percentage', 'integration_config',
            'is_active', 'status_display', 'created_at', 'updated_at'
        ]


# ========================
# VENTES
# ========================

class SaleItemSerializer(BaseModelSerializer):
    """
    Serializer pour les lignes de vente
    """
    article = ArticleListSerializer(read_only=True)
    article_id = serializers.CharField(write_only=True)
    
    article_name = serializers.CharField(read_only=True)
    article_code = serializers.CharField(read_only=True)
    
    quantity = serializers.DecimalField(max_digits=10, decimal_places=3)
    unit_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    discount_percentage = serializers.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    discount_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    line_total = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    tax_rate = serializers.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    tax_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    
    lot_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    
    class Meta:
        model = SaleItem
        fields = [
            'id', 'article', 'article_id', 'article_name', 'article_code',
            'quantity', 'unit_price', 'discount_percentage', 'discount_amount',
            'line_total', 'tax_rate', 'tax_amount', 'lot_number',
            'created_at', 'updated_at'
        ]


class PaymentSerializer(AuditableSerializer):
    """
    Serializer pour les paiements
    """
    payment_method = PaymentMethodSerializer(read_only=True)
    payment_method_id = serializers.CharField(write_only=True)
    
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    status = serializers.ChoiceField(choices=[
        ('pending', 'En attente'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
        ('cancelled', 'Annulé'),
        ('refunded', 'Remboursé'),
    ], default='pending')
    
    # Informations spécifiques
    card_last_digits = serializers.CharField(max_length=4, required=False, allow_blank=True)
    authorization_code = serializers.CharField(max_length=50, required=False, allow_blank=True)
    transaction_id = serializers.CharField(max_length=100, required=False, allow_blank=True)
    mobile_money_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    check_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    
    # Espèces
    cash_received = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    cash_change = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    
    payment_date = serializers.DateTimeField(default=timezone.now)
    notes = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = Payment
        fields = [
            'id', 'payment_method', 'payment_method_id', 'amount', 'status',
            'card_last_digits', 'authorization_code', 'transaction_id',
            'mobile_money_number', 'check_number', 'cash_received', 'cash_change',
            'payment_date', 'notes', 'created_by', 'created_at'
        ]


class DiscountSerializer(BaseModelSerializer, NamedModelSerializer, ActivableModelSerializer):
    """
    Serializer pour les remises
    """
    discount_type = serializers.ChoiceField(choices=[
        ('percentage', 'Pourcentage'),
        ('fixed_amount', 'Montant fixe'),
        ('buy_x_get_y', 'Achetez X obtenez Y'),
        ('loyalty_points', 'Points fidélité'),
    ])
    
    scope = serializers.ChoiceField(choices=[
        ('sale', 'Sur la vente totale'),
        ('category', 'Sur une catégorie'),
        ('article', 'Sur un article spécifique'),
        ('customer', 'Pour un client spécifique'),
    ])
    
    percentage_value = serializers.DecimalField(max_digits=5, decimal_places=2, required=False, allow_null=True)
    fixed_value = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    min_quantity = serializers.IntegerField(required=False, allow_null=True)
    min_amount = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    max_amount = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    
    start_date = serializers.DateTimeField()
    end_date = serializers.DateTimeField(required=False, allow_null=True)
    
    class Meta:
        model = Discount
        fields = [
            'id', 'name', 'description', 'discount_type', 'scope',
            'percentage_value', 'fixed_value', 'min_quantity', 'min_amount',
            'max_amount', 'start_date', 'end_date', 'is_active',
            'status_display', 'created_at', 'updated_at'
        ]


class SaleDiscountSerializer(BaseModelSerializer):
    """
    Serializer pour les remises appliquées à une vente
    """
    discount = DiscountSerializer(read_only=True)
    discount_id = serializers.CharField(write_only=True)
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    authorized_by = serializers.CharField(source='authorized_by.get_full_name', read_only=True)
    
    class Meta:
        model = SaleDiscount
        fields = ['id', 'discount', 'discount_id', 'amount', 'authorized_by']


class ReceiptSerializer(BaseModelSerializer):
    """
    Serializer pour les tickets de caisse
    """
    receipt_number = serializers.CharField(read_only=True)
    header_text = serializers.CharField(required=False, allow_blank=True)
    footer_text = serializers.CharField(required=False, allow_blank=True)
    printed_at = serializers.DateTimeField(read_only=True)
    print_count = serializers.IntegerField(read_only=True)
    emailed_at = serializers.DateTimeField(read_only=True)
    
    class Meta:
        model = Receipt
        fields = [
            'id', 'receipt_number', 'header_text', 'footer_text',
            'printed_at', 'print_count', 'emailed_at',
            'created_at', 'updated_at'
        ]


class SaleListSerializer(AuditableSerializer):
    """
    Serializer optimisé pour les listes de ventes
    """
    sale_number = serializers.CharField(read_only=True)
    sale_type = serializers.CharField()
    status = serializers.CharField()
    
    customer = CustomerListSerializer(read_only=True)
    cashier = serializers.CharField(source='cashier.get_full_name', read_only=True)
    
    sale_date = serializers.DateTimeField()
    total_amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    paid_amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    
    # Champs calculés
    items_count = serializers.SerializerMethodField()
    is_paid = serializers.SerializerMethodField()
    balance = serializers.SerializerMethodField()
    
    class Meta:
        model = Sale
        fields = [
            'id', 'sale_number', 'sale_type', 'status', 'customer', 'cashier',
            'sale_date', 'total_amount', 'paid_amount', 'items_count',
            'is_paid', 'balance', 'created_at'
        ]
    
    def get_items_count(self, obj):
        """Nombre d'articles dans la vente"""
        return getattr(obj, 'items_count', 0)
    
    def get_is_paid(self, obj):
        """Vérifie si la vente est payée"""
        return obj.is_paid()
    
    def get_balance(self, obj):
        """Solde restant à payer"""
        return float(obj.get_balance())


class SaleDetailSerializer(AuditableSerializer):
    """
    Serializer complet pour les ventes avec toutes les relations
    """
    sale_number = serializers.CharField(read_only=True)
    
    sale_type = serializers.ChoiceField(choices=[
        ('regular', 'Vente normale'),
        ('return', 'Retour'),
        ('exchange', 'Échange'),
        ('quote', 'Devis'),
    ])
    
    status = serializers.ChoiceField(choices=[
        ('draft', 'Brouillon'),
        ('pending', 'En attente'),
        ('completed', 'Terminée'),
        ('cancelled', 'Annulée'),
        ('refunded', 'Remboursée'),
        ('partially_refunded', 'Partiellement remboursée'),
    ])
    
    # Relations
    customer = CustomerSerializer(read_only=True)
    customer_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    
    cashier = serializers.CharField(source='cashier.get_full_name', read_only=True)
    cashier_id = serializers.CharField(write_only=True)
    
    # Dates
    sale_date = serializers.DateTimeField(default=timezone.now)
    
    # Montants
    subtotal = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    discount_amount = serializers.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    tax_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    paid_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    change_amount = serializers.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # Fidélité
    loyalty_points_earned = serializers.IntegerField(read_only=True)
    loyalty_points_used = serializers.IntegerField(default=0)
    
    # Relations imbriquées
    items = SaleItemSerializer(many=True, read_only=True)
    payments = PaymentSerializer(many=True, read_only=True)
    applied_discounts = SaleDiscountSerializer(many=True, read_only=True)
    receipt = ReceiptSerializer(read_only=True)
    
    # Vente liée
    original_sale = serializers.CharField(source='original_sale.sale_number', read_only=True)
    original_sale_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    
    # Notes
    notes = serializers.CharField(required=False, allow_blank=True)
    customer_notes = serializers.CharField(required=False, allow_blank=True)
    
    # Configuration
    receipt_printed = serializers.BooleanField(default=False)
    receipt_emailed = serializers.BooleanField(default=False)
    
    # Champs calculés
    is_paid = serializers.SerializerMethodField()
    balance = serializers.SerializerMethodField()
    can_be_returned = serializers.SerializerMethodField()
    
    class Meta:
        model = Sale
        fields = [
            'id', 'sale_number', 'sale_type', 'status',
            'customer', 'customer_id', 'cashier', 'cashier_id',
            'sale_date', 'subtotal', 'discount_amount', 'tax_amount',
            'total_amount', 'paid_amount', 'change_amount',
            'loyalty_points_earned', 'loyalty_points_used',
            'original_sale', 'original_sale_id', 'notes', 'customer_notes',
            'receipt_printed', 'receipt_emailed',
            'items', 'payments', 'applied_discounts', 'receipt',
            'is_paid', 'balance', 'can_be_returned',
            'created_by', 'created_at', 'updated_by', 'updated_at'
        ]
    
    def get_is_paid(self, obj):
        """Vérifie si la vente est payée"""
        return obj.is_paid()
    
    def get_balance(self, obj):
        """Solde restant"""
        return float(obj.get_balance())
    
    def get_can_be_returned(self, obj):
        """Peut être retournée"""
        return obj.can_be_returned()


# ========================
# OPÉRATIONS SPÉCIALES
# ========================

class CheckoutSerializer(serializers.Serializer):
    """
    Serializer pour l'opération de checkout (finaliser une vente)
    """
    customer_id = serializers.CharField(required=False, allow_null=True)
    items = serializers.ListField(child=serializers.DictField(), min_length=1)
    payments = serializers.ListField(child=serializers.DictField(), min_length=1)
    loyalty_points_to_use = serializers.IntegerField(default=0, min_value=0)
    discount_codes = serializers.ListField(child=serializers.CharField(), required=False)
    notes = serializers.CharField(required=False, allow_blank=True)
    
    def validate_items(self, value):
        """Valide les articles"""
        for item in value:
            if 'article_id' not in item:
                raise serializers.ValidationError("Chaque article doit avoir un article_id")
            if 'quantity' not in item or float(item['quantity']) <= 0:
                raise serializers.ValidationError("La quantité doit être positive")
        return value
    
    def validate_payments(self, value):
        """Valide les paiements"""
        total = sum(float(p.get('amount', 0)) for p in value)
        if total <= 0:
            raise serializers.ValidationError("Le montant total des paiements doit être positif")
        return value


class VoidSaleSerializer(serializers.Serializer):
    """
    Serializer pour annuler une vente
    """
    reason = serializers.CharField(required=True)
    authorization_code = serializers.CharField(required=False, allow_blank=True)


class ReturnSaleSerializer(serializers.Serializer):
    """
    Serializer pour retourner une vente
    """
    original_sale_id = serializers.CharField(required=True)
    items = serializers.ListField(child=serializers.DictField(), min_length=1)
    reason = serializers.CharField(required=True)
    refund_method = serializers.CharField(required=True)