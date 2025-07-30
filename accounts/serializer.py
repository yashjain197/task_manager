from rest_framework import serializers
from .models import User, Permission

DEFAULT_PERMISSIONS = {
    'Admin': [
        'manage_users',
        'manage_tasks',
        'view_reports',
    ],
    'User': [
        'view_tasks',
        'update_task_status',
    ],
}

class SignUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'email',
            'first_name',
            'last_name',
            'password',
            'role', 
            'is_verified',
        ]

        extra_kwargs = {
            'password' : {
                'write_only': True
            }
        }

    def create(self, validated_data):
        email = validated_data['email'].lower()
        first_name = validated_data['first_name'].lower()
        last_name = validated_data['last_name'].lower()
        role = validated_data['role']
        is_verified = validated_data['is_verified']

        # Create new User
        user = User.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=role,
            is_verified=is_verified,
        )
        password = validated_data['password']
        user.set_password(password)
        user.save()

        # Assign default permissions based on role
        if role in DEFAULT_PERMISSIONS:
            for perm in DEFAULT_PERMISSIONS[role]:
                Permission.objects.create(user=user, permission_name=perm)

        return user
    
class UserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model=User
        fields = [
            'email',
            'name',
        ]

    def get_name(self, obj):
        fname = obj.first_name.capitalize()
        lname = obj.last_name.capitalize()

        return fname + ' ' + lname

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'permission_name', 'created_at', 'updated_at']