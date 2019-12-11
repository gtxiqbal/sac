from rest_framework import serializers
from auto_tl1.models import GponDevice, Sto

class GponSerializer(serializers.Serializer):
    hostname = serializers.CharField()
    ip_gpon = serializers.CharField()
    sto = serializers.CharField()

    def create(self, validated_data):
        return GponDevice.objects.create(**validated_data)

class StoSerializer(serializers.ModelSerializer):
    gpon = serializers.StringRelatedField(many=True)

    class Meta:
        model = Sto
        fields = ['sto_code', 'sto_name', 'gpon',]