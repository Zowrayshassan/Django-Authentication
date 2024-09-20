# from django.shortcuts import render
# from rest_framework.views import APIView
# from .serializers import jwtSerializer
# from rest_framework.response import Response
# from django.contrib.auth import authenticate
# from .models import MyUser
# from rest_framework import status
# from rest_framework.exceptions import AuthenticationFailed
# import jwt, datetime
# from rest_framework.generics import GenericAPIView

# class RegisterView(GenericAPIView):
#     serializer_class = jwtSerializer
    
#     def post(self, request):
#         name = request.data.get('name')
#         email = request.data.get('email')
#         password = request.data.get('password')
       
#         if MyUser.objects.filter(email=email).exists() or MyUser.objects.filter(name=name).exists():
#             return Response({'message': 'Email or name already exists'}, status=status.HTTP_400_BAD_REQUEST)
    
#         if not email or not password or not name:
#             return Response({'error': 'Email, name, and password are required'}, status=status.HTTP_400_BAD_REQUEST)  
        
#         serializer = jwtSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_201_CREATED)

# class LoginView(GenericAPIView):
#     serializer_class = jwtSerializer
#     def post(self, request):
#         email = request.data.get('email')
#         password = request.data.get('password')

#         if not email or not password:
#             return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

#         user =  MyUser(email=email, password=password)

#         if user is None:
#             raise AuthenticationFailed('Invalid credentials')

#         payload = {
#             'id': user.id,
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
#             'iat': datetime.datetime.utcnow()
#         }

#         token = jwt.encode(payload, 'secret', algorithm='HS256')

#         response = Response({
#             'message': 'Login successful',
#             'token': token,
#             'id': user.id,
#             'email': user.email
#         }, status=status.HTTP_200_OK)
#         response.set_cookie(key='jwt', value=token, httponly=True)
#         return response
    
# class UserView(GenericAPIView):
#     serializer_class = jwtSerializer
#     def get(self, request):
#         token = request.COOKIES.get('jwt')
    
#         if not token:
#             raise AuthenticationFailed('Unauthenticated User!')

#         try:
#             payload = jwt.decode(token, 'secret', algorithms=['HS256'])
#         except jwt.ExpiredSignatureError:
#             return Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
       
#         user = MyUser.objects.filter(id=payload['id']).first()
#         serializer = jwtSerializer(user)
#         return Response(serializer.data)           

# class LogoutView(GenericAPIView):
#     serializer_class = jwtSerializer

#     def post(self, request):
#         response = Response()
#         response.delete_cookie('jwt')
#         response.data = {'message': 'Logout successfully'}
#         return response


from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import jwtSerializer
from rest_framework.response import Response
from django.contrib.auth import authenticate
from .models import MyUser
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.exceptions import AuthenticationFailed
import jwt , datetime

class RegisterView(GenericAPIView):
    serializer_class = jwtSerializer
    def post(self,request):
        name = request.data.get('name')
        email = request.data.get('email')
        password = request.data.get('password')
       
        if MyUser.objects.filter(email=email).exists() :
            return Response ({'message':'mail or name already exsists'})
        if MyUser.objects.filter(name=name).exists() :
            return Response ({'message':'mail or name already exsists'})
    
        if not email or not password or not name:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)  
        serializer = jwtSerializer(data=request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()
        return Response (serializer.data)
    

class LoginView(GenericAPIView):
    serializer_class = jwtSerializer
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password :
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        user = MyUser.objects.get(email=email,password=password)

        if user is None:
            raise AuthenticationFailed('User not found')
        
        payload = {
            'id' : user.id,
            'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat':datetime.datetime.utcnow()
        }
        
        token = jwt.encode(payload,'secret',algorithm='HS256')

        response_data = {
            'token': token,
            'id': user.id,
            'email': user.email , 
            'password':user.password
        }
        response = Response({'message':'login succesfully',
            **response_data}, status=status.HTTP_200_OK)
        response.set_cookie(key='jwt', value=token, httponly=True)
        return response 


class UserView(GenericAPIView):
    serializer_class = jwtSerializer
    def get(self, request):
        token = request.COOKIES.get('jwt')
    
        if not token :
            raise AuthenticationFailed('unauthenticated User !')
        try:
            payload = jwt.decode(token,'secret',algorithms=['HS256'])
        except  jwt.ExpiredSignatureError : 
           raise AuthenticationFailed('Unauthenticated User')
       
        user = MyUser.objects.filter(id=payload['id']).first()
        serializer = jwtSerializer(user)
        return Response(serializer.data)           
                
class LogoutView(GenericAPIView):
    serializer_class = jwtSerializer
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        
        response.data = {
            'message':'logout succesfully.'
        }
        return response
            