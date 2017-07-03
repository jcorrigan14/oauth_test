import json

from django.shortcuts import render

# Create your views here.

from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.decorators import login_required
from django.http.response import HttpResponse
from django.contrib.auth.models import User
from oauth2_provider.models import AccessToken,RefreshToken
from rest_framework import permissions, routers, serializers, viewsets
from datetime import datetime,timezone,timedelta
from oauth2_provider.decorators import protected_resource
import urllib.request
import requests
from DOT_tutorial.settings import *
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class ExampleView(APIView):
    """
    A view that can accept POST requests with JSON content.
    """
    #parser_classes = (JSONParser,)

    #
    # TODO: Pull Client-ID and Secret
    # TODO: Accept any type of input
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    # TODO: Create verify token method
    #

    permission_classes = (AllowAny,)
    def post(self, request, format=None):
        print("I am here")

        url='http://localhost:8000/o/token/'
        headers={'Content-Type': 'application/x-www-form-urlencoded',
                 'Authorization':'Basic VDZYc0NyMWlsbWNSb1dyQm03eGVtVkU5cVlNYW1pMG5sS0tCbldiMDpOeDZwVjF0R3Nuek5mc2k3WGNibWdXWWlMZk9yZEw1THM4cERwNlRiWWowdlRNQ3RxTUxVMk9yWHJQY3Z4V0Y4OW1LWExjc3lPN2JQbFIxUU9oSThmWTFJWkFwQUhtV1Z6V2xDQUw3MGZ0Yzd6TEo4UnNtUjBtWklBWkV4TUpVUA =='}
        if(request.data['grant_type']=='password'):
          payload='grant_type='+request.data['grant_type']+'&username='+request.data['username']+'&password='+request.data['password']

        elif(request.data['grant_type']=='refresh_token'):

            payload = 'grant_type=' + request.data['grant_type'] + '&refresh_token=' + request.data[
                'refresh_token']

        r=requests.post(url,data=payload,headers=headers)

        # make sure to remove this line
        print(r.json()["access_token"])

        a=r.json()

        return Response(a)




class userView(APIView):
    """
    A view that can accept POST requests with JSON content.
    """
    #parser_classes = (JSONParser,)



    def post(self, request):

        queryset = User.objects.all()

        serializer_class = UserSerializer(queryset,many=True)

        return Response(serializer_class.data)


