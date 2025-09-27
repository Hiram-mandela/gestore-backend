"""
Tests pour l'application authentication - GESTORE
Tests des serializers, vues et permissions - VERSION CORRIGÉE
"""
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings
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
            'password_confirm': 'DifferentPass456!',  # ❌ PASSWORD_CONFIRM DIFFÉRENT (objectif du test)
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid(), "Le serializer devrait être invalide avec des passwords différents")
        
        # Vérifier que l'erreur porte bien sur password_confirm
        self.assertIn('password_confirm', serializer.errors, 
                     f"Erreur password_confirm attendue, erreurs trouvées: {serializer.errors}")
    
    def test_duplicate_username(self):
        """Test validation unicité nom d'utilisateur"""
        # Créer premier utilisateur
        User.objects.create_user(
            username='duplicate',
            email='first@example.com',
            password='pass123'
        )
        
        # Tenter de créer avec même username
        data = {
            'username': 'duplicate',  # Déjà pris
            'email': 'second@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)


class EdgeCasesTest(TestCase):
    """Tests des cas limites et edge cases - VERSION CORRIGÉE"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier'
        )
    
    def test_user_creation_without_role(self):
        """Test création utilisateur sans rôle - CORRIGÉ"""
        user_data = {
            'username': 'noroleuser',
            'email': 'norole@example.com',
            # ✅ CORRECTION : Ajouter first_name et last_name
            'first_name': 'No',
            'last_name': 'Role',
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            # Pas de role_id - c'est le but du test
        }
        
        serializer = UserCreateSerializer(data=user_data)
        self.assertTrue(serializer.is_valid(), f"Erreurs: {serializer.errors}")
        
        user = serializer.save()
        self.assertIsNone(user.role)
    
    def test_role_without_discount_permission(self):
        """Test rôle sans permission de remise - CORRIGÉ"""
        role_data = {
            'name': 'Basic Role',  # ✅ name requis
            'role_type': 'viewer',
            'can_apply_discounts': False,
            # ✅ CORRECTION : Ajouter tous les champs boolean obligatoires
            'can_manage_users': False,
            'can_manage_inventory': False, 
            'can_manage_sales': False,
            'can_manage_suppliers': False,
            'can_view_reports': True,  # Viewer peut au moins voir les rapports
            'can_manage_reports': False,
            'can_manage_settings': False,
            'can_void_transactions': False,
            'max_discount_percent': 0.0,  # ✅ Valeur par défaut quand pas de discount
        }
        
        serializer = RoleSerializer(data=role_data)
        self.assertTrue(serializer.is_valid(), f"Erreurs: {serializer.errors}")
    
    def test_empty_password_confirm(self):
        """Test mot de passe confirm vide"""
        user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'StrongPass123!',
            'password_confirm': '',  # Vide
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=user_data)
        self.assertFalse(serializer.is_valid())
        # Doit avoir erreur password_confirm
        self.assertIn('password_confirm', serializer.errors)


class CleanupTest(TestCase):
    """Tests de nettoyage et gestion des ressources - VERSION CORRIGÉE"""
    
    def test_user_profile_cascade_delete(self):
        """Test suppression en cascade du profil - CORRIGÉ"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123'
        )
        
        # ✅ CORRECTION : Récupérer le profil existant au lieu d'en créer un nouveau
        # Le profil est créé automatiquement par signal ou dans create_user
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile_id = profile.id
        
        # Supprimer utilisateur
        user.delete()
        
        # Le profil doit être supprimé aussi (CASCADE)
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
            'max_discount_percent': 5.0,
            # Ajouter tous les champs obligatoires
            'can_manage_users': False,
            'can_manage_inventory': False,
            'can_manage_suppliers': False,
            'can_view_reports': True,
            'can_manage_reports': False,
            'can_manage_settings': False,
            'can_apply_discounts': True,
            'can_void_transactions': False,
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
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            'role_id': role_id
        }
        
        user_response = self.client.post(
            reverse('authentication:user-list'),
            user_data
        )
        
        self.assertEqual(user_response.status_code, status.HTTP_201_CREATED, 
                        f"Erreur création utilisateur: {user_response.data}")
        
        # ✅ CORRECTION : L'ID est maintenant inclus grâce à la correction du serializer
        self.assertIn('id', user_response.data, f"ID manquant dans réponse: {user_response.data}")
        user_id = user_response.data['id']
        
        # 3. Tester la connexion du nouvel utilisateur
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
    """Tests spécifiques des validations - VERSION CORRIGÉE"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier'
        )
    
    def test_password_strength_validation(self):
        """Test validation force du mot de passe - CORRIGÉ"""
        
        # ✅ CORRECTION : Données valides SAUF le password faible
        user_data = {
            'username': 'weakpassuser',
            'email': 'weak@example.com', 
            # ✅ Ajouter first_name et last_name valides
            'first_name': 'Weak',
            'last_name': 'Password',
            'password': '123',  # ❌ Password trop faible (objectif du test)
            'password_confirm': '123',
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=user_data)
        self.assertFalse(serializer.is_valid(), 
                         "Le serializer devrait être invalide avec un password faible")
        
        # Vérifier que l'erreur porte bien sur le password  
        self.assertIn('password', serializer.errors, 
                      f"Erreur password attendue, erreurs trouvées: {serializer.errors}")
    
    def test_role_discount_validation(self):
        """Test validation pourcentage de remise"""
        invalid_data = {
            'name': 'Test Role',
            'role_type': 'cashier',
            'can_apply_discounts': True,
            'max_discount_percent': 150.0,  # > 100%
            # Ajouter les champs obligatoires
            'can_manage_users': False,
            'can_manage_inventory': False,
            'can_manage_sales': True,
            'can_manage_suppliers': False,
            'can_view_reports': False,
            'can_manage_reports': False,
            'can_manage_settings': False,
            'can_void_transactions': False,
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
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            'role_id': str(self.role.id)
        }
        
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)


class APITest(APITestCase):
    """Tests des APIs REST"""
    
    def setUp(self):
        self.admin_role = Role.objects.create(
            name='Admin',
            role_type='admin',
            can_manage_users=True,
            can_manage_inventory=True,
            can_manage_sales=True
        )
        
        self.normal_role = Role.objects.create(
            name='Normal User',
            role_type='cashier',
            can_manage_sales=True
        )
        
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='admin123',
            role=self.admin_role,
            is_superuser=True
        )
        
        self.normal_user = User.objects.create_user(
            username='normal',
            email='normal@example.com',
            password='normal123',
            role=self.normal_role
        )
        
        # Créer les profils
        UserProfile.objects.get_or_create(user=self.admin_user)
        UserProfile.objects.get_or_create(user=self.normal_user)
    
    def test_user_list_api(self):
        """Test API de liste des utilisateurs"""
        self.client.force_authenticate(user=self.admin_user)
        
        url = reverse('authentication:user-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data['results']) > 0)
    
    def test_user_create_api(self):
        """Test création d'utilisateur via API"""
        self.client.force_authenticate(user=self.admin_user)
        
        url = reverse('authentication:user-list')
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'StrongPass123!',
            'password_confirm': 'StrongPass123!',
            'role_id': str(self.normal_role.id)
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['username'], 'newuser')
    
    def test_change_password_api(self):
        """Test changement de mot de passe via API"""
        self.client.force_authenticate(user=self.normal_user)
        
        url = reverse('authentication:user-change-password')
        data = {
            'current_password': 'normal123',
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
            'max_discount_percent': 5.0,
            # Ajouter tous les champs obligatoires
            'can_manage_users': False,
            'can_manage_inventory': False,
            'can_manage_suppliers': False,
            'can_view_reports': False,
            'can_manage_reports': False,
            'can_manage_settings': False,
            'can_apply_discounts': True,
            'can_void_transactions': False,
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
    
    def test_manager_can_manage_users(self):
        """Test que le manager peut gérer les utilisateurs"""
        self.assertTrue(self.manager.has_module_permission('users'))
        self.assertTrue(self.manager.has_module_permission('inventory'))
        self.assertFalse(self.manager.has_module_permission('sales'))
    
    def test_cashier_limited_permissions(self):
        """Test que le caissier a des permissions limitées"""
        self.assertFalse(self.cashier.has_module_permission('users'))
        self.assertFalse(self.cashier.has_module_permission('inventory'))
        self.assertTrue(self.cashier.has_module_permission('sales'))


class PerformanceTest(APITestCase):
    """Tests de performance - VERSION CORRIGÉE pour éviter les conflits Django Debug Toolbar"""
    
    def setUp(self):
        self.role = Role.objects.create(
            name='Test Role',
            role_type='cashier',
            can_manage_sales=True
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
        """Test performance de la liste des utilisateurs - CORRIGÉ"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('authentication:user-list')
        
        # ✅ SOLUTION ROBUSTE : Désactiver Django Debug Toolbar pour les tests
        with override_settings(
            DEBUG=True,
            MIDDLEWARE=[
                m for m in settings.MIDDLEWARE 
                if 'debug_toolbar' not in m.lower()
            ]
        ):
            initial_queries = len(connection.queries)
            response = self.client.get(url)
            final_queries = len(connection.queries)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Vérifier que le nombre de requêtes est raisonnable (optimisations)
        queries_count = final_queries - initial_queries
        self.assertLess(queries_count, 15, 
                       f"Trop de requêtes DB: {queries_count}. Optimisations nécessaires.")
    
    def test_role_list_performance(self):
        """Test performance de la liste des rôles - CORRIGÉ"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('authentication:role-list')
        
        # ✅ SOLUTION ROBUSTE : Désactiver Django Debug Toolbar pour les tests
        with override_settings(
            DEBUG=True,
            MIDDLEWARE=[
                m for m in settings.MIDDLEWARE 
                if 'debug_toolbar' not in m.lower()
            ]
        ):
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