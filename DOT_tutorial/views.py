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
    # TODO: Pull Client-ID and Secret from data (currently hardcoded)
    # TODO: Accept any type of input (just XML left to handle)
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    #

    permission_classes = (AllowAny,)
    def post(self, request, format=None):
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
# All views that don't specify "permission_classes = (AllowAny,)"
# you will have to pass a valid access token in the header in x-www-form-urlencoded format to gain access
#       i.e. header='Authorization=Bearer <access_token>'
#
class userView(APIView):

    def post(self, request):
        queryset = User.objects.all()
        serializer_class = UserSerializer(queryset,many=True)
        return Response(serializer_class.data)


class logoutView(APIView):
    #
    # For JSON Data:
    # Requires Headers {'Authorization': 'Bearer <access_token>', 'content_type': 'application/json' and
    # payload= {"token":"<token>"}
    #

    def post(self, request):
        url = 'http://localhost:8000/o/revoke_token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic UTNhUko0b2hsSlVhOXlRWDFyNTAySnFDcHpSZDJXM0VKd1Y4UkZHNDp6cXR1cGFXcnBPMGxnMW1vSDZwTmZRNlZHZDJGRWtqQ2JYMGpsdVhwRkltSmNkREpNTWM1MG5CRkR5WkpxMnNiYXp4b1E0dFZGVDcxaDZQNERTd1plRDZKVFB4dVlhSjRCYzRIVDlsYW50Q24ySm1QY0tUUnhEU3F1M1hJWnRDVg=='}
        payload='token='+request.data['access_token']

        r = requests.post(url, data=payload, headers=headers)
        return Response('Token successfully revoked')
