from ast import Delete
import email
from tkinter import Y
from urllib import response
from winreg import SetValue
from .models import *
from .serializers import *
from .emails import *
from rest_framework import generics
from rest_framework import mixins
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
import jwt
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens  import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from datetime import datetime, timedelta






class RegisterApplicantView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin,
                    mixins.UpdateModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin):

    serializer_class = RegisterApplicantSerializer
    queryset = User.objects.all()
    

    def post(self, request):
        
        serializer = RegisterApplicantSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        phone_number = request.data['phone_number']

        user_data = serializer.data
        user = User.objects.get(email = user_data['email'])


        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('verify/email')

        absurl = 'http://'+ current_site + relativeLink +"?token="+str(token)
        body = 'Hi ' + user.first_name + ' Use the link below to verify your email \n' + absurl  
        data = {'body': body, 'to': user.email, 'subject': 'Verify your email'}

        ApplicantEmail.send_email(data)

        user.phone = phone_number
        
        user.save()

        return Response(user_data)

class RegisterEmployeeView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin,

                    mixins.UpdateModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin):

    serializer_class = RegisterEmployeeSerializer
    queryset = User.objects.all()
    


    def post(self, request):
        serializer = RegisterEmployeeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        name = request.data['first_name']
        date = request.data['date_joined']
        dt = datetime.strptime(date, '%Y-%m-%d')
        username = format(name[0:3] + str(dt.year))

        user_data = serializer.data
        user = User.objects.get(email = user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('verify/email')
        
        absurl = 'http://'+ current_site + relativeLink +"?token="+str(token)
        body = 'Hi ' + user.first_name + ' Your new username is ' + username + ' Use the link below to verify your email \n' + absurl  
        data = {'body': body, 'to': user.email, 'subject': 'Your Username and Verify your email'}

        EmployeeEmail.send_email(data)

        user.username = username
        user.save()

        return Response(user_data)
        
    
class LoginApplicantView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin,
                         mixins.UpdateModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin):

    
    serializer_class = LoginApplicantSerializer
    
    queryset = User.objects.all()

    lookup_field = 'id'

    


    def post(self, request):
        phone_number = request.data['phone_number']
        email = request.data['email']
        password = request.data['password']
        # otp = request.data['otp']
        

        serializer = LoginApplicantSerializer(data=request.data)

        user = User.objects.filter(email=email).first()
        
       
        

        if serializer.is_valid():
            phone_number = serializer.data['phone_number']
            email = serializer.data['email']
            
            # otp = serializer.data['otp']
            

        # if user.otp is None:
        #    raise AuthenticationFailed('Otp not found!')


        if user is None:
            raise AuthenticationFailed('Email not found!')

        if user.phone_number != phone_number:
            raise AuthenticationFailed('Invalid phone number!')

        if user.email != email:
            raise AuthenticationFailed('Invalid email!')

        if user.role_code != "Applicant":
            raise AuthenticationFailed('Invalid role!')
        
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified!')

        if not user.check_password(password):
            raise AuthenticationFailed('Invalid password!')

        # if user.otp != otp:
        #     raise AuthenticationFailed('Invalid otp!')

        


        payload = {
            'id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=10),
            'iat': datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        
        response.set_cookie(key='Token', value=token, httponly=True)
        response.set_cookie(key='Phone', value=phone_number, httponly=True)

        
        user.save()
        
        response.data = {
            'Token': token,
            'Phone': phone_number,
            'message': 'Account verified!'
        }
        

        return response

class LoginEmployeeView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin,
                         mixins.UpdateModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin):

    
    serializer_class = LoginEmployeeSerializer
    
    queryset = User.objects.all()

    lookup_field = 'id'

    


    def post(self, request):
        username = request.data['username']
        password = request.data['password']
        
        serializer = LoginEmployeeSerializer(data=request.data)
        user = User.objects.filter(username=username).first()

        if serializer.is_valid():
            username = serializer.data['username']
            # otp = serializer.data['otp']
            

        # if user.otp is None:
        #     raise AuthenticationFailed('Otp not found!')

        if user is None:
            raise AuthenticationFailed('Username not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Invalid password!')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified!')

        if user.role_code != "Employee":
            raise AuthenticationFailed('Invalid role!')

        if user.username != username:
            raise AuthenticationFailed('Invalid Username')

        # if user.otp != otp:
        #     raise AuthenticationFailed('Invalid otp!')

        payload = {
            'id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=10),
            'iat': datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')


        response = Response()

        response.set_cookie(key='Token', value=token, httponly=True)
        response.set_cookie(key='Username', value=username, httponly=True)

        
        user.save()
        
        response.data = {
            'Token': token,
            'Username': username,
            'message': 'Account verified!'
        }
        

        return response


class VerifyEmailView(generics.GenericAPIView):

    serializers_class = VerifyEmailSerializer
    queryset = User.objects.all()
    
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'email': 'Successfully activated!'})
                
        except jwt.ExpiredSignatureError:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'], options={"verify_signature": False})
            user = User.objects.get(id=payload['user_id'])
            
            if user.is_verified:
                return Response({'token': 'Already used!'})
            
            else:
                user.delete()
            raise AuthenticationFailed('Activation Expired!')

        except jwt.exceptions.DecodeError:
            raise AuthenticationFailed('Invalid Token')

            


class ApplicantUserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('Token')
        phone_number = request.COOKIES.get('Phone')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        if not phone_number:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = RegisterApplicantSerializer(user)
        return Response(serializer.data)

class EmployeeUserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('Token')
        username = request.COOKIES.get('Username')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        if not username:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = RegisterEmployeeSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('Token')
        response.delete_cookie('Username')
        response.delete_cookie('Phone')
        response.data = {
            'message': 'You have logout successfully'
        }
        return response

