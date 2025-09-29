"""
Configuration de l'interface d'administration pour sales - GESTORE
"""
from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Sum
from .models import (
    Customer, PaymentMethod, Sale, SaleItem, Payment,
    Discount, SaleDiscount, Receipt
)


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = [
        'customer_code', 'get_full_name_display', 'customer_type',
        'email', 'phone', 'loyalty_points', 'total_purchases',
        'purchase_count', 'is_active'
    ]
    list_filter = ['customer_type', 'is_active', 'marketing_consent']
    search_fields = ['customer_code', 'first_name', 'last_name', 'company_name', 'email', 'phone']
    ordering = ['last_name', 'first_name', 'company_name']
    readonly_fields = ['customer_code', 'loyalty_points', 'total_purchases', 'purchase_count', 'last_purchase_date']
    
    fieldsets = (
        ('Identification', {
            'fields': ('customer_code', 'customer_type', 'name', 'description')
        }),
        ('Personne', {
            'fields': ('first_name', 'last_name'),
            'classes': ('collapse',)
        }),
        ('Entreprise', {
            'fields': ('company_name', 'tax_number'),
            'classes': ('collapse',)
        }),
        ('Contact', {
            'fields': ('email', 'phone', 'address', 'city', 'postal_code', 'country')
        }),
        ('Fidélité', {
            'fields': ('loyalty_card_number', 'loyalty_points')
        }),
        ('Statistiques', {
            'fields': ('total_purchases', 'purchase_count', 'last_purchase_date'),
            'classes': ('collapse',)
        }),
        ('Préférences', {
            'fields': ('preferred_payment_method', 'marketing_consent', 'is_active')
        }),
    )
    
    def get_full_name_display(self, obj):
        return obj.get_full_name()
    get_full_name_display.short_description = 'Nom complet'


@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = ['name', 'payment_type', 'requires_authorization', 'max_amount', 'fee_percentage', 'is_active']
    list_filter = ['payment_type', 'is_active', 'requires_authorization']
    search_fields = ['name']
    ordering = ['payment_type', 'name']


class SaleItemInline(admin.TabularInline):
    model = SaleItem
    extra = 0
    fields = ['article', 'quantity', 'unit_price', 'discount_percentage', 'line_total', 'tax_amount']
    readonly_fields = ['line_total', 'tax_amount']


class PaymentInline(admin.TabularInline):
    model = Payment
    extra = 0
    fields = ['payment_method', 'amount', 'status', 'payment_date']
    readonly_fields = ['payment_date']


@admin.register(Sale)
class SaleAdmin(admin.ModelAdmin):
    list_display = [
        'sale_number', 'sale_date', 'customer', 'cashier',
        'total_amount', 'paid_amount', 'status_badge', 'sale_type'
    ]
    list_filter = ['status', 'sale_type', 'sale_date', 'cashier']
    search_fields = ['sale_number', 'customer__customer_code', 'customer__first_name', 'customer__last_name']
    ordering = ['-sale_date']
    date_hierarchy = 'sale_date'
    readonly_fields = [
        'sale_number', 'subtotal', 'tax_amount', 'total_amount',
        'paid_amount', 'loyalty_points_earned', 'created_by', 'created_at'
    ]
    inlines = [SaleItemInline, PaymentInline]
    
    fieldsets = (
        ('Identification', {
            'fields': ('sale_number', 'sale_type', 'status')
        }),
        ('Acteurs', {
            'fields': ('customer', 'cashier')
        }),
        ('Montants', {
            'fields': (
                'subtotal', 'discount_amount', 'tax_amount',
                'total_amount', 'paid_amount', 'change_amount'
            )
        }),
        ('Fidélité', {
            'fields': ('loyalty_points_earned', 'loyalty_points_used')
        }),
        ('Informations supplémentaires', {
            'fields': ('original_sale', 'notes', 'customer_notes', 'receipt_printed', 'receipt_emailed'),
            'classes': ('collapse',)
        }),
        ('Métadonnées', {
            'fields': ('created_by', 'created_at'),
            'classes': ('collapse',)
        }),
    )
    
    def status_badge(self, obj):
        colors = {
            'draft': 'gray',
            'pending': 'orange',
            'completed': 'green',
            'cancelled': 'red',
            'refunded': 'purple'
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Statut'


@admin.register(Discount)
class DiscountAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'discount_type', 'scope', 'value_display',
        'start_date', 'end_date', 'is_active_now'
    ]
    list_filter = ['discount_type', 'scope', 'is_active', 'start_date']
    search_fields = ['name', 'description']
    ordering = ['-start_date']
    
    fieldsets = (
        ('Identification', {
            'fields': ('name', 'description', 'discount_type', 'scope')
        }),
        ('Valeurs', {
            'fields': ('percentage_value', 'fixed_value')
        }),
        ('Conditions', {
            'fields': ('min_quantity', 'min_amount', 'max_amount')
        }),
        ('Période', {
            'fields': ('start_date', 'end_date', 'is_active')
        }),
    )
    
    def value_display(self, obj):
        if obj.discount_type == 'percentage' and obj.percentage_value:
            return f"{obj.percentage_value}%"
        elif obj.discount_type == 'fixed_amount' and obj.fixed_value:
            return f"{obj.fixed_value} €"
        return "-"
    value_display.short_description = 'Valeur'
    
    def is_active_now(self, obj):
        from django.utils import timezone
        now = timezone.now()
        is_active = (
            obj.is_active and
            obj.start_date <= now and
            (obj.end_date is None or obj.end_date >= now)
        )
        return format_html(
            '<span style="color: {};">{}</span>',
            'green' if is_active else 'red',
            '✓' if is_active else '✗'
        )
    is_active_now.short_description = 'Active maintenant'


@admin.register(Receipt)
class ReceiptAdmin(admin.ModelAdmin):
    list_display = ['receipt_number', 'sale', 'print_count', 'printed_at', 'emailed_at']
    list_filter = ['printed_at', 'emailed_at']
    search_fields = ['receipt_number', 'sale__sale_number']
    ordering = ['-created_at']
    readonly_fields = ['receipt_number', 'print_count', 'printed_at', 'emailed_at']