"""
Tests pour l'application authentication - GESTORE
Tests des serializers, vues et permissions
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Role, UserProfile
from .serializers import UserSerializer, RoleSerializer, UserCreateSerializer

User = get_user_model()


class RoleModelTest(TestCase):
    """Tests du modèle Role"""
    
    def setUp(self):
        self.role_data = {
            'name': 'Test Manager',
            'description': 'Rôle de test',
            'role_type': 'manager',
            'can_manage_users': True,
            'can_manage_inventory': True,
            'can_manage_sales': True,
            'max_discount_percent': 15.0
        }
    
    def test_create_role(self):
        """Test création d'un rôle"""
        role = Role.objects.create(**self.role_data)
        self.assertEqual(role.name, 'Test Manager')
        self.assertEqual(role.role_type, 'manager')
        self.assertTrue(role.can_manage_users)
        self.assertEqual(role.max_discount_percent, 15.0)
    
    def test_role_str(self):
        """Test représentation string du rôle"""
        role = Role.objects.create(**self.role_data)
        self.assertEqual(str(role), 'Test Manager')


class UserModelTest(TestCase):
    """Tests du modèle User personnalisé"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier',
            can_manage_sales=True
        )
        
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'role': self.role
        }
    
    def test_create_user(self):
        """Test création d'un utilisateur"""
        user = User.objects.create_user(
            password='testpass123',
            **self.user_data
        )
        
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.employee_code.startswith('EMP'))
        self.assertIsNotNone(user.profile)  # Profil créé automatiquement
    
    def test_user_account_locking(self):
        """Test verrouillage de compte"""
        user = User.objects.create_user(
            password='testpass123',
            **self.user_data
        )
        
        # Tester le verrouillage
        user.lock_account(30)
        self.assertTrue(user.is_account_locked())
        
        # Tester le déverrouillage
        user.unlock_account()
        self.assertFalse(user.is_account_locked())
    
    def test_failed_login_attempts(self):
        """Test comptage des tentatives échouées"""
        user = User.objects.create_user(
            password='testpass123',
            **self.user_data
        )
        
        # Incrémenter les tentatives
        user.increment_failed_login()
        user.increment_failed_login()
        self.assertEqual(user.failed_login_attempts, 2)
        
        # Le 3ème échec doit verrouiller le compte
        user.increment_failed_login()
        self.assertTrue(user.is_account_locked())


class RoleSerializerTest(TestCase):
    """Tests du serializer Role"""
    
    def test_role_serialization(self):
        """Test sérialisation d'un rôle"""
        role = Role.objects.create(
            name='Test Role',
            role_type='manager',
            can_manage_users=True,
            max_discount_percent=10.0
        )
        
        serializer = RoleSerializer(role)
        data = serializer.data
        
        self.assertEqual(data['name'], 'Test Role')
        self.assertEqual(data['role_type'], 'manager')
        self.assertTrue(data['can_manage_users'])
        self.assertEqual(data['max_discount_percent'], 10.0)
        self.assertIn('permissions_summary', data)
        self.assertIn('users_count', data)
    
    def test_role_validation(self):
        """Test validation du serializer Role"""
        invalid_data = {
            'name': '',  # Nom vide
            'role_type': 'manager',
            'max_discount_percent': 150.0  # Pourcentage invalide
        }
        
        serializer = RoleSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('max_discount_percent', serializer.errors)


class UserSerializerTest(TestCase):
    """Tests du serializer User"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier'
        )
    
    def test_user_creation_serializer(self):
        """Test création d'utilisateur via serializer"""
        user_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=user_data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        
        user = serializer.save()
        self.assertEqual(user.username, 'newuser')
        self.assertEqual(user.role, self.role)
        self.assertTrue(user.check_password('StrongPass123!'))
    
    def test_user_validation(self):
        """Test validation utilisateur"""
        # Email déjà existant
        User.objects.create_user(
            username='existing',
            email='existing@example.com',
            password='pass123'
        )
        
        invalid_data = {
            'username': 'newuser',
            'email': 'existing@example.com',  # Email déjà pris
            'password': 'weak',  # Mot de passe trop faible
            'password_confirm': 'different'  # Mots de passe différents
        }
        
        serializer = UserCreateSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertIn('password', serializer.errors)


class AuthenticationAPITest(APITestCase):
    """Tests des APIs d'authentification"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Manager',
            role_type='manager',
            can_manage_users=True
        )
        
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            role=self.role,
            is_superuser=True
        )
        
        self.normal_user = User.objects.create_user(
            username='user',
            email='user@example.com', 
            password='userpass123'
        )
    
    def test_login_api(self):
        """Test API de connexion"""
        url = reverse('authentication:login')
        data = {
            'username': 'admin',
            'password': 'adminpass123'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)
    
    def test_login_invalid_credentials(self):
        """Test connexion avec credentials invalides"""
        url = reverse('authentication:login')
        data = {
            'username': 'admin',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_user_list_api_requires_permission(self):
        """Test que la liste des utilisateurs nécessite des permissions"""
        url = reverse('authentication:user-list')
        
        # Sans authentification
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Avec utilisateur normal (pas de permission)
        self.client.force_authenticate(user=self.normal_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Avec admin (a les permissions)
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_user_profile_api(self):
        """Test API de profil utilisateur"""
        self.client.force_authenticate(user=self.normal_user)
        
        url = reverse('authentication:user-profile')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'user')
    
    def test_change_password_api(self):
        """Test API de changement de mot de passe"""
        self.client.force_authenticate(user=self.normal_user)
        
        url = reverse('authentication:user-change-password')
        data = {
            'current_password': 'userpass123',
            'new_password': 'NewStrongPass123!',
            'new_password_confirm': 'NewStrongPass123!'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Vérifier que le mot de passe a changé
        self.normal_user.refresh_from_db()
        self.assertTrue(self.normal_user.check_password('NewStrongPass123!'))
    
    def test_role_list_api(self):
        """Test API de liste des rôles"""
        self.client.force_authenticate(user=self.admin_user)
        
        url = reverse('authentication:role-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data['results']) > 0)
    
    def test_role_create_api(self):
        """Test création de rôle via API"""
        self.client.force_authenticate(user=self.admin_user)
        
        url = reverse('authentication:role-list')
        data = {
            'name': 'New Role',
            'role_type': 'seller',
            'can_manage_sales': True,
            'max_discount_percent': 5.0
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Role')


class PermissionsTest(TestCase):
    """Tests des permissions personnalisées"""
    
    def setUp(self):
        self.manager_role = Role.objects.create(
            name='Manager',
            role_type='manager',
            can_manage_users=True,
            can_manage_inventory=True
        )
        
        self.cashier_role = Role.objects.create(
            name='Cashier',
            role_type='cashier',
            can_manage_sales=True
        )
        
        self.manager = User.objects.create_user(
            username='manager',
            email='manager@example.com',
            password='pass123',
            role=self.manager_role
        )
        
        self.cashier = User.objects.create_user(
            username='cashier',
            email='cashier@example.com',
            password='pass123',
            role=self.cashier_role
        )
    
    def test_role_based_permissions(self):
        """Test permissions basées sur les rôles"""
        from apps.core.permissions import CanManageUsers, CanManageInventory
        
        # Mock request
        class MockRequest:
            def __init__(self, user):
                self.user = user
        
        # Test permission gestion utilisateurs
        can_manage_users = CanManageUsers()
        
        # Manager peut gérer les utilisateurs
        request = MockRequest(self.manager)
        self.assertTrue(can_manage_users.has_permission(request, None))
        
        # Cashier ne peut pas gérer les utilisateurs
        request = MockRequest(self.cashier)
        self.assertFalse(can_manage_users.has_permission(request, None))


class PerformanceTest(APITestCase):
    """Tests de performance des APIs"""
    
    def setUp(self):
        # Créer plusieurs utilisateurs pour tester les performances
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier'
        )
        
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='pass123',
            is_superuser=True
        )
        
        # Créer 50 utilisateurs de test
        users = []
        for i in range(50):
            user = User(
                username=f'user{i}',
                email=f'user{i}@example.com',
                role=self.role
            )
            user.set_password('pass123')
            users.append(user)
        
        User.objects.bulk_create(users)
    
    def test_user_list_performance(self):
        """Test performance de la liste des utilisateurs"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('authentication:user-list')
        
        # Mesurer le nombre de requêtes
        from django.test.utils import override_settings
        from django.db import connection
        
        with override_settings(DEBUG=True):
            initial_queries = len(connection.queries)
            response = self.client.get(url)
            final_queries = len(connection.queries)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Vérifier que le nombre de requêtes est raisonnable (optimisations)
        queries_count = final_queries - initial_queries
        self.assertLess(queries_count, 10, 
                       f"Trop de requêtes DB: {queries_count}. Optimisations nécessaires.")