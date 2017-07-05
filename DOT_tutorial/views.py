# Create your views here.

import requests
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


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

        a=r.json()

        return Response(a)



#
#
#
class userView(APIView):
    """
    A view that can accept POST requests with JSON content.
    """
    #parser_classes = (JSONParser,)
#
    #
    #The post function requires a parameter i.e the user token always to run
    # on passing the correct token this displays the user data
    # header format is  "Authorization: Bearer <API ACCESS KEY>"
    #


    def post(self, request):

        queryset = User.objects.all()

        serializer_class = UserSerializer(queryset,many=True)

        return Response(serializer_class.data)


class logoutview(APIView):
    def post(self,request):
        #
        # header format is  "Authorization: Bearer <API ACCESS KEY>"
        #Always requires a user token as a request header to enter here
        #In this function a call to revoke this token is made.
        #on a 200 response from the server the output is blank, so we can send anything as a response and the frontend can handle that
        #

        url = 'http://localhost:8000/o/revoke_token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic VDZYc0NyMWlsbWNSb1dyQm03eGVtVkU5cVlNYW1pMG5sS0tCbldiMDpOeDZwVjF0R3Nuek5mc2k3WGNibWdXWWlMZk9yZEw1THM4cERwNlRiWWowdlRNQ3RxTUxVMk9yWHJQY3Z4V0Y4OW1LWExjc3lPN2JQbFIxUU9oSThmWTFJWkFwQUhtV1Z6V2xDQUw3MGZ0Yzd6TEo4UnNtUjBtWklBWkV4TUpVUA ==' }

        payload='token='+request.data['access_token']
        payload1 = 'token=' + request.data['refresh_token']

        r = requests.post(url, data=payload, headers=headers)

        r1 = requests.post(url, data=payload1, headers=headers)

        return Response("You have logged out")

