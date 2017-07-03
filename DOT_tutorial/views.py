from django.shortcuts import render

# Create your views here.

from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
import urllib.request
import requests

# Due to the multiple possible formats of POST data, this is a custom API view to be called before Oauth2's o/token
# in order to determine the format of data input and pass it to o/token accordingly
#


class ExampleView(APIView):
    #parser_classes = (JSONParser,)

    #
    # TODO: Pull Client-ID and Secret
    # TODO: Accept any type of input
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    # TODO: Create verify token method
    #

    def post(self, request, format=None):
        print("I am here")
        url='http://localhost:8000/o/token/'
        headers={'Content-Type': 'application/x-www-form-urlencoded',
             'Authorization':'Basic UTNhUko0b2hsSlVhOXlRWDFyNTAySnFDcHpSZDJXM0VKd1Y4UkZHNDp6cXR1cGFXcnBPMGxnMW1vSDZwTmZRNlZHZDJGRWtqQ2JYMGpsdVhwRkltSmNkREpNTWM1MG5CRkR5WkpxMnNiYXp4b1E0dFZGVDcxaDZQNERTd1plRDZKVFB4dVlhSjRCYzRIVDlsYW50Q24ySm1QY0tUUnhEU3F1M1hJWnRDVg=='}

        if request.data['grant_type']=='password':
            payload='grant_type='+request.data['grant_type']+'&username='+request.data['username']+'&password='+request.data['password']
        elif request.data['grant_type']=='refresh_token':
            payload = 'grant_type=' + request.data['grant_type'] + '&refresh_token='+request.data['refresh_token']


        r=requests.post(url,data=payload,headers=headers)

        # make sure to remove this line
        print(r.json()["access_token"])

        a=r.json()

        return Response(a)