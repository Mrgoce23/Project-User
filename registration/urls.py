from django.urls import path
from .views import *

urlpatterns = [
    path('register/applicant', RegisterApplicantView.as_view()),
    path('register/employee', RegisterEmployeeView.as_view()),

    path('login/applicant', LoginApplicantView.as_view()),
    path('login/employee', LoginEmployeeView.as_view()),

    path('verify/email', VerifyEmailView.as_view(), name = "verify/email"),

    path('user/applicant', ApplicantUserView.as_view()),
    path('user/employee', EmployeeUserView.as_view()),

    path('logout', LogoutView.as_view()),
]