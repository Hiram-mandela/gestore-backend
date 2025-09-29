"""
Tests pour l'application sales - GESTORE
Tests complets des modèles, serializers, vues et permissions
"""
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from decimal import Decimal
from django.db import connection
from datetime import timedelta

from apps.authentication.models import Role
from apps.inventory.models import Article, Category, UnitOfMeasure, Location, Stock
from .models import (
    Customer, PaymentMethod, Sale, SaleItem, Payment,
    Discount, SaleDiscount, Receipt
)
from .serializers import (
    CustomerSerializer, PaymentMethodSerializer, SaleListSerializer,
    SaleDetailSerializer, DiscountSerializer
)

User = get_user_model()


# ========================
# TESTS DES MODÈLES
# ========================

class CustomerModelTest(TestCase):
    """Tests du modèle Customer"""
    
    def setUp(self):
        self.customer_data = {
            'name': 'Test Customer',
            'customer_type': 'individual',
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john.doe@example.com',
            'phone': '0123456789',
            'is_active': True
        }
    
    def test_create_customer(self):
        """Test création d'un client"""
        customer = Customer.objects.create(**self.customer_data)
        self.assertEqual(customer.first_name, 'John')
        self.assertEqual(customer.last_name, 'Doe')
        self.assertTrue(customer.customer_code.startswith('CLI'))
    
    def test_customer_code_auto_generation(self):
        """Test génération automatique du code client"""
        customer = Customer.objects.create(**self.customer_data)
        self.assertIsNotNone(customer.customer_code)
        self.assertTrue(customer.customer_code.startswith('CLI'))
    
    def test_get_full_name(self):
        """Test récupération du nom complet"""
        customer = Customer.objects.create(**self.customer_data)
        self.assertEqual(customer.get_full_name(), 'John Doe')
    
    def test_company_customer(self):
        """Test client entreprise"""
        customer = Customer.objects.create(
            name='Company Test',
            customer_type='company',
            company_name='ACME Corp',
            is_active=True
        )
        self.assertEqual(customer.get_full_name(), 'ACME Corp')
    
    def test_add_loyalty_points(self):
        """Test ajout de points de fidélité"""
        customer = Customer.objects.create(**self.customer_data)
        initial_points = customer.loyalty_points
        
        customer.add_loyalty_points(100)
        self.assertEqual(customer.loyalty_points, initial_points + 100)
    
    def test_can_use_loyalty_points(self):
        """Test vérification des points disponibles"""
        customer = Customer.objects.create(**self.customer_data)
        customer.loyalty_points = 50
        customer.save()
        
        self.assertTrue(customer.can_use_loyalty_points(30))
        self.assertFalse(customer.can_use_loyalty_points(60))


class PaymentMethodModelTest(TestCase):
    """Tests du modèle PaymentMethod"""
    
    def test_create_payment_method(self):
        """Test création d'un moyen de paiement"""
        payment_method = PaymentMethod.objects.create(
            name='Espèces',
            payment_type='cash',
            is_active=True
        )
        self.assertEqual(payment_method.name, 'Espèces')
        self.assertEqual(payment_method.payment_type, 'cash')


class SaleModelTest(TestCase):
    """Tests du modèle Sale"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Cashier',
            role_type='cashier',
            can_manage_sales=True
        )
        
        self.user = User.objects.create_user(
            username='cashier',
            email='cashier@example.com',
            password='pass123',
            role=self.role
        )
        
        self.customer = Customer.objects.create(
            name='Test Customer',
            customer_type='individual',
            first_name='John',
            last_name='Doe',
            is_active=True
        )
    
    def test_create_sale(self):
        """Test création d'une vente"""
        sale = Sale.objects.create(
            sale_type='regular',
            status='draft',
            customer=self.customer,
            cashier=self.user
        )
        
        self.assertIsNotNone(sale.sale_number)
        self.assertTrue(sale.sale_number.startswith('VTE'))
        self.assertEqual(sale.status, 'draft')
    
    def test_sale_number_auto_generation(self):
        """Test génération automatique du numéro de vente"""
        sale = Sale.objects.create(
            sale_type='regular',
            status='draft',
            cashier=self.user
        )
        
        self.assertIsNotNone(sale.sale_number)
        today = timezone.now().date()
        expected_prefix = f"VTE{today.strftime('%Y%m%d')}"
        self.assertTrue(sale.sale_number.startswith(expected_prefix))
    
    def test_is_paid(self):
        """Test vérification du paiement"""
        sale = Sale.objects.create(
            sale_type='regular',
            status='completed',
            cashier=self.user,
            total_amount=Decimal('100.00'),
            paid_amount=Decimal('100.00')
        )
        
        self.assertTrue(sale.is_paid())
        
        sale.paid_amount = Decimal('50.00')
        sale.save()
        
        self.assertFalse(sale.is_paid())
    
    def test_get_balance(self):
        """Test calcul du solde restant"""
        sale = Sale.objects.create(
            sale_type='regular',
            status='pending',
            cashier=self.user,
            total_amount=Decimal('100.00'),
            paid_amount=Decimal('60.00')
        )
        
        self.assertEqual(sale.get_balance(), Decimal('40.00'))
    
    def test_can_be_returned(self):
        """Test vérification de possibilité de retour"""
        sale = Sale.objects.create(
            sale_type='regular',
            status='completed',
            cashier=self.user,
            sale_date=timezone.now()
        )
        
        self.assertTrue(sale.can_be_returned())
        
        # Vente ancienne (> 30 jours)
        old_sale = Sale.objects.create(
            sale_type='regular',
            status='completed',
            cashier=self.user,
            sale_date=timezone.now() - timedelta(days=35)
        )
        
        self.assertFalse(old_sale.can_be_returned())


class DiscountModelTest(TestCase):
    """Tests du modèle Discount"""
    
    def test_create_percentage_discount(self):
        """Test création d'une remise en pourcentage"""
        discount = Discount.objects.create(
            name='Remise 10%',
            discount_type='percentage',
            scope='sale',
            percentage_value=Decimal('10.00'),
            start_date=timezone.now(),
            is_active=True
        )
        
        self.assertEqual(discount.discount_type, 'percentage')
        self.assertEqual(discount.percentage_value, Decimal('10.00'))
    
    def test_calculate_percentage_discount(self):
        """Test calcul d'une remise en pourcentage"""
        discount = Discount.objects.create(
            name='Remise 10%',
            discount_type='percentage',
            scope='sale',
            percentage_value=Decimal('10.00'),
            start_date=timezone.now(),
            is_active=True
        )
        
        amount = Decimal('100.00')
        discount_amount = discount.calculate_discount(amount)
        
        self.assertEqual(discount_amount, Decimal('10.00'))
    
    def test_calculate_fixed_discount(self):
        """Test calcul d'une remise fixe"""
        discount = Discount.objects.create(
            name='Remise 5€',
            discount_type='fixed_amount',
            scope='sale',
            fixed_value=Decimal('5.00'),
            start_date=timezone.now(),
            is_active=True
        )
        
        amount = Decimal('50.00')
        discount_amount = discount.calculate_discount(amount)
        
        self.assertEqual(discount_amount, Decimal('5.00'))


# ========================
# TESTS DES SERIALIZERS
# ========================

class CustomerSerializerTest(TestCase):
    """Tests du serializer Customer"""
    
    def test_serializer_with_valid_data(self):
        """Test serializer avec données valides"""
        data = {
            'name': 'Test Customer',
            'customer_type': 'individual',
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'phone': '0123456789',
            'is_active': True
        }
        
        serializer = CustomerSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        
        customer = serializer.save()
        self.assertEqual(customer.first_name, 'John')
        self.assertEqual(customer.last_name, 'Doe')
    
    def test_company_customer_validation(self):
        """Test validation client entreprise"""
        data = {
            'name': 'Company Test',
            'customer_type': 'company',
            # company_name manquant
            'is_active': True
        }
        
        serializer = CustomerSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('company_name', serializer.errors)


# ========================
# TESTS DES APIs
# ========================

class SalesAPITest(APITestCase):
    """Tests des APIs REST de sales"""
    
    def setUp(self):
        # Créer les rôles
        self.admin_role = Role.objects.create(
            name='Admin',
            role_type='admin',
            can_manage_sales=True,
            can_manage_users=True,
            can_void_transactions=True,
            can_apply_discounts=True,
            max_discount_percent=Decimal('50.00')
        )
        
        self.cashier_role = Role.objects.create(
            name='Cashier',
            role_type='cashier',
            can_manage_sales=True,
            can_apply_discounts=True,
            max_discount_percent=Decimal('10.00')
        )
        
        # Créer les utilisateurs
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='admin123',
            role=self.admin_role,
            is_superuser=True
        )
        
        self.cashier_user = User.objects.create_user(
            username='cashier',
            email='cashier@example.com',
            password='cashier123',
            role=self.cashier_role
        )
        
        # Créer données de test
        self.payment_method = PaymentMethod.objects.create(
            name='Espèces',
            payment_type='cash',
            is_active=True
        )
        
        # Créer données inventory pour les tests
        self.unit = UnitOfMeasure.objects.create(
            name='Pièce',
            symbol='pcs',
            is_active=True
        )
        
        self.category = Category.objects.create(
            name='Test Category',
            code='TEST',
            is_active=True
        )
        
        self.article = Article.objects.create(
            name='Test Article',
            code='ART001',
            category=self.category,
            unit_of_measure=self.unit,
            purchase_price=Decimal('10.00'),
            selling_price=Decimal('15.00'),
            is_active=True,
            is_sellable=True,
            manage_stock=True
        )
        
        self.location = Location.objects.create(
            name='Magasin',
            code='MAG01',
            location_type='store',
            is_active=True
        )
        
        self.stock = Stock.objects.create(
            article=self.article,
            location=self.location,
            quantity_on_hand=Decimal('100.0'),
            quantity_available=Decimal('100.0'),
            unit_cost=Decimal('10.00')
        )
    
    def test_customer_list(self):
        """Test liste des clients"""
        self.client.force_authenticate(user=self.cashier_user)
        
        # Créer un client
        Customer.objects.create(
            name='Test Customer',
            customer_type='individual',
            first_name='John',
            last_name='Doe',
            is_active=True
        )
        
        url = reverse('sales:customer-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data['results']) > 0)
    
    def test_customer_create(self):
        """Test création d'un client"""
        self.client.force_authenticate(user=self.cashier_user)
        
        url = reverse('sales:customer-list')
        data = {
            'name': 'New Customer',
            'customer_type': 'individual',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'email': 'jane@example.com',
            'phone': '0987654321',
            'is_active': True
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['first_name'], 'Jane')
    
    def test_payment_method_list(self):
        """Test liste des moyens de paiement"""
        self.client.force_authenticate(user=self.cashier_user)
        
        url = reverse('sales:paymentmethod-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data['results']) > 0)
    
    def test_pos_checkout_simple(self):
        """Test checkout POS simple"""
        self.client.force_authenticate(user=self.cashier_user)
        
        url = reverse('sales:pos-checkout')
        data = {
            'items': [
                {
                    'article_id': str(self.article.id),
                    'quantity': 2
                }
            ],
            'payments': [
                {
                    'payment_method_id': str(self.payment_method.id),
                    'amount': 30.00,
                    'cash_received': 50.00,
                    'cash_change': 20.00
                }
            ]
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('sale', response.data)
        
        # Vérifier que le stock a été mis à jour
        self.stock.refresh_from_db()
        self.assertEqual(self.stock.quantity_on_hand, Decimal('98.0'))
    
    def test_pos_search_article(self):
        """Test recherche d'article au POS"""
        self.client.force_authenticate(user=self.cashier_user)
        
        url = reverse('sales:pos-search-article')
        response = self.client.get(url, {'q': 'Test'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data['results']) > 0)


# ========================
# TESTS DES PERMISSIONS
# ========================

class SalesPermissionsTest(TestCase):
    """Tests des permissions de sales"""
    
    def setUp(self):
        self.admin_role = Role.objects.create(
            name='Admin',
            role_type='admin',
            can_manage_sales=True,
            can_void_transactions=True
        )
        
        self.cashier_role = Role.objects.create(
            name='Cashier',
            role_type='cashier',
            can_manage_sales=True
        )
        
        self.viewer_role = Role.objects.create(
            name='Viewer',
            role_type='viewer',
            can_manage_sales=False
        )
        
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='pass123',
            role=self.admin_role
        )
        
        self.cashier = User.objects.create_user(
            username='cashier',
            email='cashier@example.com',
            password='pass123',
            role=self.cashier_role
        )
        
        self.viewer = User.objects.create_user(
            username='viewer',
            email='viewer@example.com',
            password='pass123',
            role=self.viewer_role
        )
    
    def test_admin_can_manage_sales(self):
        """Test que l'admin peut gérer les ventes"""
        self.assertTrue(self.admin.has_module_permission('sales'))
        self.assertTrue(self.admin.role.can_manage_sales)
        self.assertTrue(self.admin.role.can_void_transactions)
    
    def test_cashier_can_manage_sales(self):
        """Test que le caissier peut gérer les ventes"""
        self.assertTrue(self.cashier.has_module_permission('sales'))
        self.assertTrue(self.cashier.role.can_manage_sales)
        self.assertFalse(self.cashier.role.can_void_transactions)
    
    def test_viewer_cannot_manage_sales(self):
        """Test que le viewer ne peut pas gérer les ventes"""
        self.assertFalse(self.viewer.has_module_permission('sales'))
        self.assertFalse(self.viewer.role.can_manage_sales)


# ========================
# TESTS DE WORKFLOW COMPLET
# ========================

class SalesWorkflowTest(APITestCase):
    """Tests de workflow complet de vente"""
    
    def setUp(self):
        # Créer le rôle cashier
        self.cashier_role = Role.objects.create(
            name='Cashier',
            role_type='cashier',
            can_manage_sales=True,
            can_apply_discounts=True,
            max_discount_percent=Decimal('10.00')
        )
        
        self.cashier = User.objects.create_user(
            username='cashier',
            email='cashier@example.com',
            password='cashier123',
            role=self.cashier_role
        )
        
        self.client.force_authenticate(user=self.cashier)
        
        # Créer les données nécessaires
        self.payment_method = PaymentMethod.objects.create(
            name='Espèces',
            payment_type='cash',
            is_active=True
        )
        
        self.unit = UnitOfMeasure.objects.create(
            name='Pièce',
            symbol='pcs',
            is_active=True
        )
        
        self.category = Category.objects.create(
            name='Test',
            code='TEST',
            is_active=True
        )
        
        self.article = Article.objects.create(
            name='Test Article',
            code='ART001',
            category=self.category,
            unit_of_measure=self.unit,
            purchase_price=Decimal('10.00'),
            selling_price=Decimal('15.00'),
            is_active=True,
            is_sellable=True,
            manage_stock=True
        )
        
        self.location = Location.objects.create(
            name='Magasin',
            code='MAG01',
            location_type='store',
            is_active=True
        )
        
        self.stock = Stock.objects.create(
            article=self.article,
            location=self.location,
            quantity_on_hand=Decimal('100.0'),
            quantity_available=Decimal('100.0'),
            unit_cost=Decimal('10.00')
        )
    
    def test_complete_sale_workflow(self):
        """Test workflow complet : checkout → vérification stock → paiement"""
        
        # 1. Créer un client
        customer_url = reverse('sales:customer-list')
        customer_data = {
            'name': 'Test Customer',
            'customer_type': 'individual',
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'is_active': True
        }
        
        customer_response = self.client.post(customer_url, customer_data, format='json')
        self.assertEqual(customer_response.status_code, status.HTTP_201_CREATED)
        customer_id = customer_response.data['id']
        
        # 2. Effectuer un checkout
        checkout_url = reverse('sales:pos-checkout')
        checkout_data = {
            'customer_id': customer_id,
            'items': [
                {
                    'article_id': str(self.article.id),
                    'quantity': 3
                }
            ],
            'payments': [
                {
                    'payment_method_id': str(self.payment_method.id),
                    'amount': 45.00,
                    'cash_received': 50.00,
                    'cash_change': 5.00
                }
            ]
        }
        
        checkout_response = self.client.post(checkout_url, checkout_data, format='json')
        self.assertEqual(checkout_response.status_code, status.HTTP_201_CREATED)
        
        sale_id = checkout_response.data['sale']['id']
        
        # 3. Vérifier que la vente a été créée correctement
        sale = Sale.objects.get(id=sale_id)
        self.assertEqual(sale.status, 'completed')
        self.assertEqual(sale.items.count(), 1)
        self.assertEqual(sale.payments.count(), 1)
        
        # 4. Vérifier que le stock a été mis à jour
        self.stock.refresh_from_db()
        self.assertEqual(self.stock.quantity_on_hand, Decimal('97.0'))
        self.assertEqual(self.stock.quantity_available, Decimal('97.0'))
        
        # 5. Vérifier les statistiques client
        customer = Customer.objects.get(id=customer_id)
        self.assertEqual(customer.purchase_count, 1)
        self.assertGreater(customer.total_purchases, Decimal('0.00'))