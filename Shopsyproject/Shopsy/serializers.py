# from rest_framework import serializers
# import re

# class SignupSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     mobile = serializers.CharField(max_length=15)
#     name = serializers.CharField(max_length=100)
#     password = serializers.CharField(write_only=True, min_length=6)

#     def validate_password(self, value):
#         """Check if password is strong"""
#         if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$', value):
#             raise serializers.ValidationError("Password must be at least 6 characters long and contain both letters and numbers.")
#         return value
