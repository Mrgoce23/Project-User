from email.policy import default
from unittest.util import _MAX_LENGTH
from rest_framework import serializers
from .models import *




class RegisterApplicantSerializer(serializers.ModelSerializer):
    role_code = serializers.HiddenField(default='Applicant', initial='Applicant')
    
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'password', 'first_name', 'last_name', 'email', 'birth_date', 'role_code']
        
        extra_kwargs = {
            'password': {'write_only': True},
            
        }


    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class RegisterEmployeeSerializer(serializers.ModelSerializer):
    role_code = serializers.HiddenField(default='Employee', initial='Employee')
    
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'password', 'first_name', 'last_name', 'email', 'birth_date', 'date_joined', 'role_code']
        extra_kwargs = {
            'password': {'write_only': True}
            
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance



class LoginApplicantSerializer(serializers.ModelSerializer):
    class Meta:
       
        model = User
        fields = ['id', 'phone_number', 'email', 'password'] 
        extra_kwargs = {
            'password': {'write_only': True},
        }


class LoginEmployeeSerializer(serializers.ModelSerializer):
    class Meta:
       
        model = User
        fields = ['id', 'username', 'password'] 
        extra_kwargs = {
            'password': {'write_only': True},
            
        }


class VerifyEmailSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['token']