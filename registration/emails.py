from email import message
from urllib import request
from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from .models import *
from .serializers import *



class EmployeeEmail:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to']])
        email.send()

class ApplicantEmail:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to']])
        email.send()



