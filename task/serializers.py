from rest_framework import serializers
from .models import Task
from accounts.models import User
from accounts.serializer import UserSerializer

class TaskSerializer(serializers.ModelSerializer):
    assigned_to = UserSerializer(read_only=True)
    created_by = UserSerializer(read_only=True)
    assigned_to_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='assigned_to', write_only=True, required=False
    )
    created_by_id = serializers.PrimaryKeyRelatedField(  # Add this for completeness
        read_only=True, source='created_by'
    )

    class Meta:
        model = Task
        fields = [
            'id', 'title', 'description', 'status', 'priority',
            'due_date', 'assigned_to', 'assigned_to_id', 'created_by', 'created_by_id',  # Add created_by_id
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_by', 'created_at', 'updated_at', 'created_by_id']  # Add created_by_id to read-only

    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)
