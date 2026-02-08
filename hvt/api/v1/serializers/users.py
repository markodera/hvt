from rest_framework import serializers
from hvt.apps.users.models import User
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer

class CustomRegisterSerializer(RegisterSerializer):
    """Custom registration serializer without username"""
    username = None

    class Meta: 
        model = User
        fields = ["email", "password1", "password2", "first_name", "last_name"]

    def get_cleaned_data(self):
        return {
            "email": self.validated_data.get("email", ""),
            "password1": self.validated_data.get("password1", ""),
            "first_name": self.validated_data.get("first_name", ""),
            "last_name": self.validated_data.get("last_name", ""),
        }
    

class CustomLoginSerializer(LoginSerializer):
    """
    Custom login serializer to use email only and extract user info
    """

    username = None

    def get_fields(self):
        fields = super().get_fields()
        fields.pop("username", None)
        return fields
    
class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    full_name = serializers.ReadOnlyField()
    role_display = serializers.CharField(source="get_role_display", read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "organization",
            "role",
            "role_display",
            "is_active",
            "is_test",
            "created_at",
        ]
        read_only_fields = ["id", "email","organization", "is_test", "created_at"]

class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating users (Admin only)."""
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ["email", "password", "first_name", "last_name", "organization", "role"]

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
class UserRoleUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user role only."""

    class Meta:
        model = User
        fields = ["role"]

        def validate_role(self, value):
            if value not in [choice[0] for choice in User.Role.choices]:
                raise serializers.ValidationError(f"Invalid role must be one of: {', '.join([c[0] for c in User.Role.choices])}")
            return value
        
class OrganizationMemberSerializer(serializers.ModelSerializer):
    """Serializer for listing organization members when role with info."""
    full_name = serializers.ReadOnlyField()
    role_display = serializers.CharField(source="get_role_display", read_only=True)
    can_be_promoted = serializers.SerializerMethodField()
    can_be_demoted = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "organization",
            "role",
            "role_display",
            "is_active",
            "is_test",
            "created_at",
            "can_be_promoted",
            "can_be_demoted",
        ]

        read_only_fields = fields

    def get_can_be_promoted(self, obj):
        """Check if a user can be promoted to a higher role."""
        return obj.role in ["member", "admin"]
    def get_can_be_demoted(self, obj):
        """Check if a user can be demoted to a lower role."""
        return obj.role in ["owner", "admin"]