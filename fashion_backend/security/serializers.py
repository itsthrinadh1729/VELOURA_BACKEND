from rest_framework import serializers
from .models import ThreatLog

class ThreatLogSerializer(serializers.ModelSerializer):
    status = serializers.CharField(source='attack_type')

    class Meta:
        model = ThreatLog
        fields = ['id', 'ip', 'status']