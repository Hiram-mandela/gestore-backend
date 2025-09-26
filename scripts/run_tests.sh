#!/bin/bash
# Script d'exécution des tests

echo "🧪 Exécution des tests GESTORE"

# Activer l'environnement virtuel
source venv/Scripts/activate

# Tests avec coverage
pytest --cov=apps --cov-report=html --cov-report=term-missing

echo "✅ Tests terminés. Rapport disponible dans htmlcov/"
