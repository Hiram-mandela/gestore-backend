"""
Tests pour l'application authentication - GESTORE
Tests des serializers, vues et permissions - VERSION CORRIGÉE
"""
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import connection

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
        
        # Vérifier que le profil a été créé
        self.assertTrue(hasattr(user, 'profile'))
    
    def test_user_validation(self):
        """Test validation utilisateur - CORRIGÉ pour garantir password_confirm"""
        
        # STRATÉGIE: Données VALIDES individuellement mais INVALIDES globalement
        invalid_data = {
            'username': 'testuser',
            'email': 'valid@email.com',  # EMAIL VALIDE pour passer validation champ
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'ValidPass123!',  # PASSWORD VALIDE pour passer validation champ
            'password_confirm': 'DifferentPass456!',  # DIFFÉRENT -> erreur validate() globale
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        
        # Maintenant password_confirm DOIT être présent
        self.assertIn('password_confirm', serializer.errors)
    
    def test_email_unique_validation(self):
        """Test validation email unique séparé"""
        # Créer un utilisateur existant
        User.objects.create_user(
            username='existing',
            email='existing@example.com',
            password='pass123'
        )
        
        # Tenter de créer avec le même email
        invalid_data = {
            'username': 'newuser',
            'email': 'existing@example.com',  # Email déjà pris
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)


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
        
        # Créer les profils manuellement pour éviter les erreurs
        UserProfile.objects.get_or_create(user=self.admin_user)
        UserProfile.objects.get_or_create(user=self.normal_user)
    
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
        from apps.core.permissions import CanManageUsers
        
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


# Désactiver debug toolbar pour éviter les erreurs de namespace
@override_settings(
    INSTALLED_APPS=[app for app in getattr(__import__('django.conf').conf.settings, 'INSTALLED_APPS', []) 
                   if 'debug_toolbar' not in app],
    MIDDLEWARE=[m for m in getattr(__import__('django.conf').conf.settings, 'MIDDLEWARE', []) 
               if 'debug_toolbar' not in m]
)
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
        UserProfile.objects.get_or_create(user=self.admin)
        
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
        
        # Créer les profils pour les utilisateurs créés
        profiles = []
        for user in User.objects.filter(username__startswith='user'):
            profiles.append(UserProfile(user=user))
        UserProfile.objects.bulk_create(profiles, ignore_conflicts=True)
    
    def test_user_list_performance(self):
        """Test performance de la liste des utilisateurs"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('authentication:user-list')
        
        # Mesurer le nombre de requêtes avec debug désactivé
        with override_settings(DEBUG=True):
            initial_queries = len(connection.queries)
            response = self.client.get(url)
            final_queries = len(connection.queries)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Vérifier que le nombre de requêtes est raisonnable (optimisations)
        queries_count = final_queries - initial_queries
        self.assertLess(queries_count, 15, 
                       f"Trop de requêtes DB: {queries_count}. Optimisations nécessaires.")
    
    def test_role_list_performance(self):
        """Test performance de la liste des rôles"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('authentication:role-list')
        
        with override_settings(DEBUG=True):
            initial_queries = len(connection.queries)
            response = self.client.get(url)
            final_queries = len(connection.queries)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Les rôles devraient nécessiter peu de requêtes
        queries_count = final_queries - initial_queries
        self.assertLess(queries_count, 5, 
                       f"Trop de requêtes DB pour les rôles: {queries_count}")


class SecurityTest(TestCase):
    """Tests de sécurité"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier'
        )
        
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            role=self.role
        )
    
    def test_password_hashing(self):
        """Test que les mots de passe sont bien hashés"""
        # Le mot de passe ne doit jamais être stocké en clair
        self.assertNotEqual(self.user.password, 'testpass123')
        self.assertTrue(self.user.check_password('testpass123'))
    
    def test_employee_code_uniqueness(self):
        """Test unicité du code employé"""
        user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='pass123'
        )
        
        user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='pass123'
        )
        
        # Les codes employés doivent être différents
        self.assertNotEqual(user1.employee_code, user2.employee_code)
    
    def test_account_lockout_mechanism(self):
        """Test mécanisme de verrouillage de compte"""
        # Simuler 3 tentatives échouées
        for _ in range(3):
            self.user.increment_failed_login()
        
        # Le compte doit être verrouillé
        self.assertTrue(self.user.is_account_locked())
        
        # Déverrouiller et vérifier
        self.user.unlock_account()
        self.assertFalse(self.user.is_account_locked())
        self.assertEqual(self.user.failed_login_attempts, 0)


class IntegrationTest(APITestCase):
    """Tests d'intégration de bout en bout"""
    
    def setUp(self):
        self.admin_role = Role.objects.create(
            name='Admin',
            role_type='admin',
            can_manage_users=True,
            can_manage_inventory=True,
            can_manage_sales=True
        )
        
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='admin123',
            role=self.admin_role,
            is_superuser=True
        )
        UserProfile.objects.get_or_create(user=self.admin)
    
    def test_complete_user_lifecycle(self):
        """Test cycle de vie complet d'un utilisateur - CORRIGÉ"""
        self.client.force_authenticate(user=self.admin)
        
        # 1. Créer un nouveau rôle
        role_data = {
            'name': 'Test Cashier',
            'role_type': 'cashier',
            'can_manage_sales': True,
            'max_discount_percent': 5.0
        }
        
        role_response = self.client.post(
            reverse('authentication:role-list'), 
            role_data
        )
        self.assertEqual(role_response.status_code, status.HTTP_201_CREATED)
        role_id = role_response.data['id']
        
        # 2. Créer un nouvel utilisateur avec ce rôle - DONNÉES PARFAITEMENT VALIDES
        user_data = {
            'username': 'newcashier',
            'email': 'cashier@example.com',
            'first_name': 'New',
            'last_name': 'Cashier',
            'password': 'StrongPass123!',  # Password VALIDE et FORT
            'password_confirm': 'StrongPass123!',  # EXACTEMENT IDENTIQUE
            'role_id': role_id
        }
        
        user_response = self.client.post(
            reverse('authentication:user-list'),
            user_data
        )
        
        # CORRECTION: Vérifier erreurs avant d'accéder à 'id'
        if user_response.status_code != status.HTTP_201_CREATED:
            self.fail(f"Création utilisateur échouée: {user_response.data}")
        
        self.assertEqual(user_response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', user_response.data, f"ID manquant dans réponse: {user_response.data}")
        user_id = user_response.data['id']
        
        # 3. Vérifier que l'utilisateur peut se connecter
        login_data = {
            'username': 'newcashier',
            'password': 'StrongPass123!'
        }
        
        login_response = self.client.post(
            reverse('authentication:login'),
            login_data
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', login_response.data)
        
        # 4. Vérifier les permissions du nouvel utilisateur
        new_user = User.objects.get(id=user_id)
        self.assertTrue(new_user.has_module_permission('sales'))
        self.assertFalse(new_user.has_module_permission('users'))
        
        # 5. Modifier l'utilisateur
        update_data = {
            'first_name': 'Updated'
        }
        
        update_response = self.client.patch(
            reverse('authentication:user-detail', kwargs={'pk': user_id}),
            update_data
        )
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        self.assertEqual(update_response.data['first_name'], 'Updated')


class ValidationTest(TestCase):
    """Tests spécifiques des validations"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier'
        )
    
    def test_password_strength_validation(self):
        """Test validation force du mot de passe"""
        weak_passwords = [
            '123',  # Trop court
            'password',  # Trop simple
            '12345678',  # Que des chiffres
        ]
        
        for weak_pwd in weak_passwords:
            data = {
                'username': 'testuser',
                'email': 'test@example.com',
                'password': weak_pwd,
                'password_confirm': weak_pwd,
                'role_id': str(self.role.id)
            }
            
            serializer = UserCreateSerializer(data=data)
            self.assertFalse(serializer.is_valid())
            # Doit avoir une erreur de password
            self.assertIn('password', serializer.errors)
    
    def test_role_discount_validation(self):
        """Test validation pourcentage de remise"""
        invalid_data = {
            'name': 'Test Role',
            'role_type': 'cashier',
            'can_apply_discounts': True,
            'max_discount_percent': 150.0  # > 100%
        }
        
        serializer = RoleSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('max_discount_percent', serializer.errors)
    
    def test_username_uniqueness(self):
        """Test unicité nom d'utilisateur"""
        # Créer premier utilisateur
        User.objects.create_user(
            username='testuser',
            email='test1@example.com',
            password='pass123'
        )
        
        # Tenter de créer avec même username
        data = {
            'username': 'testuser',  # Déjà pris
            'email': 'test2@example.com',
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)


class EdgeCasesTest(TestCase):
    """Tests des cas limites et edge cases"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier'
        )
    
    def test_user_creation_without_role(self):
        """Test création utilisateur sans rôle"""
        user_data = {
            'username': 'noroleuser',
            'email': 'norole@example.com',
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            # Pas de role_id
        }
        
        serializer = UserCreateSerializer(data=user_data)
        self.assertTrue(serializer.is_valid())
        
        user = serializer.save()
        self.assertIsNone(user.role)
    
    def test_role_without_discount_permission(self):
        """Test rôle sans permission de remise"""
        role_data = {
            'name': 'Basic Role',
            'role_type': 'viewer',
            'can_apply_discounts': False,
            # Pas de max_discount_percent
        }
        
        serializer = RoleSerializer(data=role_data)
        self.assertTrue(serializer.is_valid())
    
    def test_empty_password_confirm(self):
        """Test mot de passe confirm vide"""
        user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'StrongPass123!',
            'password_confirm': '',  # Vide
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=user_data)
        self.assertFalse(serializer.is_valid())
        # Doit avoir erreur password_confirm
        self.assertIn('password_confirm', serializer.errors)


class CleanupTest(TestCase):
    """Tests de nettoyage et gestion des ressources"""
    
    def test_user_profile_cascade_delete(self):
        """Test suppression en cascade du profil"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123'
        )
        
        # Créer profil
        profile = UserProfile.objects.create(user=user)
        profile_id = profile.id
        
        # Supprimer utilisateur
        user.delete()
        
        # Le profil doit être supprimé aussi
        self.assertFalse(UserProfile.objects.filter(id=profile_id).exists())
    
    def test_role_protection_on_delete(self):
        """Test protection du rôle lors de suppression"""
        role = Role.objects.create(
            name='Protected Role',
            role_type='manager'
        )
        
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123',
            role=role
        )
        
        # Tenter de supprimer le rôle doit échouer (PROTECT)
        with self.assertRaises(Exception):
            role.delete()
        
        # L'utilisateur doit toujours exister
        self.assertTrue(User.objects.filter(id=user.id).exists())