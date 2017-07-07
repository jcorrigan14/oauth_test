# Create your views here.

import requests
from django.contrib.auth.models import User, Group
from oauth2_provider.decorators import protected_resource
from oauth2_provider.views import ProtectedResourceView, ScopedProtectedResourceView, ReadWriteScopedResourceView
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from oauth2_provider.models import AccessToken, AbstractApplication, Application as OauthApp
from guardian.shortcuts import assign_perm, get_perms

from DOT_tutorial.models import *
from DOT_tutorial.models import Application as My_App


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
                 'Authorization':'Basic UDhmZlZHUEhwNTFRVnNnSm9TS1RROHkwV0RLdHZnU0RPVXVvQ1ZSMjp0Wm0ydXl4Z1lRd25IclBJM3ZVcDJGWjlndjgwaDlhN1VDUmxJZ1VXekJLMkZUZDRpR000OWUwV3VrcWVOZ0RmbjFCcUFkV2RDY3NVc0NVajd2bXByclZ4RTY4NGVzVUZ3eFNYQXUyNERXM01icGZoTlBDODRYWmQyTHBYTk0xUA=='}
        if(request.data['grant_type']=='password'):
            payload='grant_type='+request.data['grant_type']+'&username='+request.data['username']+'&password='+request.data['password']

        # check user group to assign proper scopes
            # could be get_or_404
            try:
                user = User.objects.get(username=request.data['username'])
            except:
                return Response("User does not exist")

            app=My_App.objects.get(pk=1) #TODO: MAKE SURE TO DETERMINE APPLICATION THAT THE USER IS REQUESTING ACCESS TO

            scopes = get_perms_as_urlencoded(user,app)
            payload += '&scope='+scopes
            print(payload)


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
class userView(ReadWriteScopedResourceView, APIView):
    required_scopes = ['groups']
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
        #payload1 = 'token=' + request.data['refresh_token']

        r = requests.post(url, data=payload, headers=headers)
        accesstokendelete=AccessToken.delete(token=request.data['access_token'])



        return Response("You have logged out")

# Basic eTB1d2JyS2FWdHZ4cEJZUFBwOWZ6dDNER1lzRzdqeE0zdlNBRnk0UzpSQ21tbXRmRkFYbGJiUUFZMmVxRnBEWVJVZXc2NGR0NkNtYkdaaHF1WVlNcEx5REFmOXF2aGgwVDd4M2k4YkRYNGxHYUFoWmtxUWtmcDd4eTFScG1TRFdxZGp3Wkt4N2djZG5CaU1GUmlUMVk5bnFFT3JmUFZvRFZ1cFpwalBlRQ==

def roles_init_new(app):
    '''
    Create new groups for Admin and student and associates them with specified Applications
    Automatically appends the Application name to the Group name 
    
    :parameter app - Application name that the Groups will be associated with
    '''
    g1 = Group.objects.get_or_create(name='%s: Admin' % app.name)[0]
    g2 = Group.objects.get_or_create(name='%s: Student' % app.name)[0]

    # ADMIN ALL GROUPS #
    # assign_perm('change_Application', g1, app)  # change Application details
    assign_perm('change_registration', g1, app)  # change submission settings
    assign_perm('change_submission', g1, app)  # change registration setup
    assign_perm('view_registration_admin', g1, app)  # change registration tools
    assign_perm('add_users', g1, app)  # user create functionality
    assign_perm('write', g1, app)  # write permissions
    assign_perm('read', g1, app)  # read permissions

    # STUDENT GROUPS #
    assign_perm('read', g2, app)  # read permissions

    ApplicationGroup.objects.get_or_create(group=g1, application=app)
    ApplicationGroup.objects.get_or_create(group=g2, application=app)

    return True

def user_roles(user):
    '''
    Return a list of all the user roles for every Application
    '''
    try:
        g = Group.objects.filter(user=user)
        ge_list = []

        for group in g:
            if ApplicationGroup.objects.filter(group=group).exists():
                ge = ApplicationGroup.objects.get(group=group)
                ge_list.append(ge)
    except:
        ge_list = []

    return {'USER_ROLES': ge_list}

def get_perms_as_urlencoded(user,app):
    a = get_perms(user,app)

    b = ' '.join(a)
    print(b)
    return b


#
# Can use OAuth2 Application's instead of my own
#
def get_app():
    print(OauthApp.objects.get(name='test'))

