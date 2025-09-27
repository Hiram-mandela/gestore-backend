# GESTORE Backend

**Système de gestion intégré pour commerces de détail**

## 🎯 Description

GESTORE est une solution logicielle complète pour la gestion des commerces de détail (magasins, pharmacies, supermarchés). Ce repository contient le backend Django avec API REST.

## 🚀 Fonctionnalités

- **Gestion des stocks** : Articles, catégories, emplacements, traçabilité des lots
- **Point de vente** : Transactions, paiements multiples, remises, fidélité
- **Gestion des fournisseurs** : Commandes, livraisons, facturation
- **Synchronisation** : Mode online/offline avec résolution de conflits
- **Rapports** : Tableaux de bord, KPIs, exports multi-formats
- **Sécurité** : Authentification JWT, rôles granulaires, audit trail
- **Licences** : Système commercial avec protection anti-piratage

## 🛠️ Technologies

- **Backend** : Django 5.2.6 + Django REST Framework
- **Base de données** : PostgreSQL 15+ / SQLite (développement)
- **Cache** : Redis
- **Authentification** : JWT avec refresh tokens
- **Documentation** : OpenAPI/Swagger

## 🏗️ Architecture

```
gestore_backend/
├── apps/
│   ├── authentication/    # Gestion utilisateurs et sécurité
│   ├── inventory/         # Gestion des stocks
│   ├── sales/            # Point de vente
│   ├── suppliers/        # Fournisseurs
│   ├── reporting/        # Rapports et analytics
│   ├── sync/             # Synchronisation
│   └── licensing/        # Système de licence
├── gestore/              # Configuration Django
└── requirements/         # Dépendances
```

## 📋 Prérequis

- Python 3.12+
- PostgreSQL 15+ (production) ou SQLite (développement)
- Redis 7+ (optionnel pour cache)

## 🚀 Installation

```bash
# Cloner le repository
git clone https://github.com/YOUR_USERNAME/gestore-backend.git
cd gestore-backend

# Créer l'environnement virtuel
python -m venv venv
source venv/Scripts/activate  # Windows
# source venv/bin/activate    # Linux/Mac

# Installer les dépendances
pip install -r requirements/development.txt

# Configuration
cp .env.example .env
# Éditer .env avec vos paramètres

# Migrations
python manage.py migrate

# Créer un superuser
python manage.py createsuperuser

# Lancer le serveur
python manage.py runserver
```

## 📚 API Documentation

- **Swagger UI** : http://localhost:8000/api/docs/
- **API Root** : http://localhost:8000/api/
- **Admin** : http://localhost:8000/admin/

## 🧪 Tests

```bash
# Lancer tous les tests
python manage.py test

# Tests avec coverage
pytest --cov=apps --cov-report=html
```

## 📈 Statut du Projet

- **Phase 1** : Fondations et modèles ✅ (70% complété)
- **Phase 2** : API REST Framework 🔄 (en cours)
- **Phase 3** : Application Flutter Desktop 📋 (planifié)
- **Phase 4** : Modules spécialisés 📋 (planifié)

## 🤝 Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Commit les changements (`git commit -m 'Ajouter nouvelle fonctionnalité'`)
4. Push vers la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Ouvrir une Pull Request

## 📄 Licence

Ce projet est sous licence propriétaire. Voir le fichier `LICENSE` pour plus de détails.

## 📞 Contact

- **Développeur** : [Votre Nom]
- **Email** : votre.email@example.com
- **Projet** : GESTORE v1.0.0
