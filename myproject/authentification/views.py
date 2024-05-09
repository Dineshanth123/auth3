from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from django.shortcuts import render,redirect
from django.contrib.auth.forms import UserCreationForm
from .forms import CustomUserCreationForm
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.hashers import make_password

class HomeView(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request):
        content = {'message': 'Welcome to the JWT Authentication page using React Js and Django!'}
        return Response(content)


class LogoutView(APIView):
     permission_classes = (IsAuthenticated,)
     def post(self, request):
          
          try:
               refresh_token = request.data["refresh_token"]
               token = RefreshToken(refresh_token)
               token.blacklist()
               return Response(status=status.HTTP_205_RESET_CONTENT)
          except Exception as e:
               return Response(status=status.HTTP_400_BAD_REQUEST)




class RegisterAPIView(APIView):
    def post(self, request):
        name = request.data.get("username")
        email = request.data.get("email")
        pass1 = request.data.get("password1")
        pass2 = request.data.get("password2")

        if pass1 == pass2:
            # Create user
            user = User.objects.create(username=name, email=email, password=make_password(pass1))
            user.is_staff = True
            user.is_superuser = True
            user.save()

            messages.success(request, "User created successfully.")
            return Response({"message": "User created successfully."}, status=status.HTTP_201_CREATED)
        else:
            messages.warning(request, "Password mismatched.")
            return Response({"message": "Password mismatched."}, status=status.HTTP_400_BAD_REQUEST)
