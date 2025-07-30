import threading
from django.contrib.auth import authenticate
from django.shortcuts import render
from django.core.mail import send_mail
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from task_manager import settings
from .utils import generate_otp
from .models import OTP, User, Permission
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from .serializer import SignUpSerializer, UserSerializer, PermissionSerializer
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.http import JsonResponse
from django.http import Http404
from django.db import IntegrityError

def get_auth_for_user(user):
    tokens = RefreshToken.for_user(user)
    return {
        'user':UserSerializer(user).data,
        'tokens': {
            'access': str(tokens.access_token),
            'refresh': str(tokens),
        }
    }

class SigninView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:    
            return Response(status=400)
        try:
            user = User.objects.get(email=email)
        except Exception as e:
            return Response({
                'status': 400,
                'success': False,
                'message': 'User Does Not Exist'
            })
            
        user = authenticate(email=email, password=password)
       
        try:
            check_user = User.objects.get(email = user)
            role = check_user.role
            is_verified= check_user.is_verified
            if not check_user.is_verified:
                return Response({
                        "success": False,
                        "status": 400,
                        "message": "user not verified",
                        "is_verified": False
                    })
        except:
            return Response({
                        "success": False,
                        "status": 400,
                        "message": "Wrong Password"
                    })
        
        user_data = get_auth_for_user(user)
        user_data["user_role"] = role
        user_data["is_verified"] = is_verified
        output = {
                "success": True,
                "status":200,
                "data": user_data,
            }
        return Response(output, status=status.HTTP_200_OK)

class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        role = request.data.get('role', '')
        email = request.data.get('email', '')

        try:
            existing_user = User.objects.get(email=email)
            output = {
                    "success": False,
                    "status": 400,
                    "message": "user already exists",
                }
            return Response(output, status=status.HTTP_200_OK)
        except Exception as e:
            existing_user = False

       
        is_verified = False
       

        data = request.data
        data['is_verified'] = is_verified

        new_user = SignUpSerializer(data=data)
        if new_user.is_valid():
            user = new_user.save()
            
            userEmail = request.data.get('email', '')
            otp = generate_otp(userEmail)
            subject = "OTP for Task manager"
            message = "OTP for Task manager verification is {}".format(otp.otp)
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [userEmail,]
            threading.Thread(target=send_mail, args=(subject, message, email_from, recipient_list)).start()

            return Response({
                            "success": True,
                            "status": 200,
                            "message": "Otp sent successfully",
                                })
        else:
            return Response(new_user.errors, status=status.HTTP_200_OK)
        
class verifyOTP(APIView):
     permission_classes = [AllowAny]

     def post(self, request):
        email = request.data.get('email')
        enteredOTP = request.data.get('otp')
        try:
            otp = OTP.objects.get(email=email)
            if otp.is_valid(enteredOTP):
                otp.delete()
                user = User.objects.get(email=email)
                user.is_verified = True
                user.save()
                user_data = get_auth_for_user(user=user)
                user_data["user_role"] = user.role
                return Response({
                    "success": True,
                    "status": 200,
                    "message": "OTP verified successfully",
                    "data": user_data
                })
            else:
                return Response({
                        "success": False,
                        "status": 400,
                        "message": "OTP Expired or Incorrect OTP"
                    })
                
        except Exception as e:
            print(e)
            return Response({
                        "success": False,
                        "status": 404,
                        "message": "user or existing otp not found"
                    })

class SendOTP(APIView):
    def post(self, request):
        userEmail = request.data.get('email', '')
        try:
            is_user_exist = User.objects.get(email = userEmail)
        except:
            return Response({
                'success': False,
                'status': 404,
                'message': 'user not found'
                }, status=status.HTTP_200_OK)
        otp = generate_otp(userEmail)
        subject = "OTP for Task manager"
        message = "OTP for Task manager verification is {}".format(otp.otp)
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [userEmail,]
        threading.Thread(target=send_mail, args=(subject, message, email_from, recipient_list)).start()

        return Response({
                        "success": True,
                        "status": 200,
                        "message": "Otp sent successfully",
                            })

class FetchUserView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        role = request.query_params.get("role")
        print(role)
        if role is not None:
            user = User.objects.filter(role=role).order_by('first_name')
        else:
            user = User.objects.all().order_by('first_name')
        data = []
        for item in user:
            if item.first_name is not "":
                userData = {
                    "id": item.id,
                    "name": item.first_name + " " + item.last_name,
                    "department": item.department
                }
                data.append(userData)
        
        return Response({
            "success": True,
            "status": 200,
            "message": "successful GET request",
            "data": data
        }, status=status.HTTP_200_OK)

class ResetPasswordView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = settings.FRONTEND_URL + f"/sign-up/reset-password/?uid={uid}&token={token}"
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.email,]

            send_mail('Password Reset', f'Use the link below to reset your password: {reset_url}', email_from, recipient_list)
            return JsonResponse({
                'status': 200,
                'success': True,
                'message': 'Password reset link has been sent to your email.'
                })
        except User.DoesNotExist:
            return JsonResponse({
                'status': 400,
                'success': True,
                'message': 'User with this email does not exist.'
                })

class ConfirmResetPasswordView(APIView):
    permission_classes = (AllowAny, )

    def post(self, request):
        uid = request.query_params.get("uid")
        token = request.query_params.get("token")
        if request.data.get('new_password') is None or uid is None or token is None:
            return Response({
                "status": 400,
                "success": False,
                "message": "Data Not Provided"
            })
        try:
            uid = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                new_password = request.data.get('new_password')
                user.set_password(new_password)
                user.save()
                return Response({
                    "status": 200,
                    "success": True,
                    "message": 'Password has been reset successfully.'
                    })
            else:
                return JsonResponse({
                    "status": 400,
                    "success": False,
                    "message": 'Invalid token.'
                    },)
        except Exception as e:
            return Response({
                "status": 400,
                "success": False,
                "message": "Some error occurred",
                "error": e
            })

class PermissionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role == 'Admin':
            user_id = request.query_params.get('user_id', request.user.id)
        else:
            user_id = request.user.id

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'status': 404,
                'message': 'User not found'
            }, status=status.HTTP_200_OK)

        permissions = Permission.objects.filter(user=user)
        serializer = PermissionSerializer(permissions, many=True)
        return Response({
            'success': True,
            'status': 200,
            'data': serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request):
        if request.user.role != 'Admin':
            return Response({
                'success': False,
                'status': 403,
                'message': 'Only Admins can create permissions'
            }, status=status.HTTP_200_OK)

        try:
            serializer = PermissionSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'status': 201,
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({
                'success': False,
                'status': 400,
                'message': serializer.errors
            }, status=status.HTTP_200_OK)
        except IntegrityError:
            return Response({
                'success': False,
                'status': 400,
                'message': 'Permission already exists for this user'
            }, status=status.HTTP_200_OK)

class PermissionDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Permission.objects.get(pk=pk)
        except Permission.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        permission = self.get_object(pk)
        serializer = PermissionSerializer(permission)
        return Response(serializer.data)

    def put(self, request, pk):
        if request.user.role != 'Admin':
            return Response({
                'success': False,
                'status': 403,
                'message': 'Only Admins can update permissions'
            }, status=status.HTTP_200_OK)

        permission = self.get_object(pk)
        serializer = PermissionSerializer(permission, data=request.data)
        try:
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'status': 200,
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                'success': False,
                'status': 400,
                'message': serializer.errors
            }, status=status.HTTP_200_OK)
        except IntegrityError:
            return Response({
                'success': False,
                'status': 400,
                'message': 'Permission already exists for this user'
            }, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        if request.user.role != 'Admin':
            return Response({
                'success': False,
                'status': 403,
                'message': 'Only Admins can delete permissions'
            }, status=status.HTTP_200_OK)

        permission = self.get_object(pk)
        permission.delete()
        return Response({
            'success': True,
            'status': 204,
            'message': 'Permission deleted successfully'
        }, status=status.HTTP_200_OK)