"""
Vues pour l'application core
"""
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.response import Response

# Les vues seront définies dans les prochaines phases

class HealthCheckView(APIView):
    """Vue de vérification de santé pour core"""
    permission_classes = []
    
    def get(self, request):
        return Response({"status": "ok", "app": "core"})
