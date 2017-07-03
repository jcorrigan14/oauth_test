from django.shortcuts import render

# Create your views here.

from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
import urllib.request
import requests
class ExampleView(APIView):
    """
    A view that can accept POST requests with JSON content.
    """
    #parser_classes = (JSONParser,)

    def post(self, request, format=None):
        print("I am here")
        url='http://localhost:8000/o/token/'
        headers={'Content-Type': 'application/x-www-form-urlencoded',
                 'Authorization':'Basic VDZYc0NyMWlsbWNSb1dyQm03eGVtVkU5cVlNYW1pMG5sS0tCbldiMDpOeDZwVjF0R3Nuek5mc2k3WGNibWdXWWlMZk9yZEw1THM4cERwNlRiWWowdlRNQ3RxTUxVMk9yWHJQY3Z4V0Y4OW1LWExjc3lPN2JQbFIxUU9oSThmWTFJWkFwQUhtV1Z6V2xDQUw3MGZ0Yzd6TEo4UnNtUjBtWklBWkV4TUpVUA =='}
        payload='grant_type='+request.data['grant_type']+'&username='+request.data['username']+'&password='+request.data['password']

        r=requests.post(url,data=payload,headers=headers)


        print(r.json()["access_token"])

        a=r.json()

        return Response(a)