# Create your views here.
from base64 import b64encode

import requests
from django.contrib.auth.models import User
from guardian.shortcuts import assign_perm, get_perms
from oauth2_provider.models import AccessToken, RefreshToken, clear_expired
from oauth2_provider.views import ReadWriteScopedResourceView
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from DOT_tutorial.settings import OAUTH2_PROVIDER
from django.shortcuts import render

from DOT_tutorial.models import *


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class LoginView(APIView):
    """
    A view that can accept POST requests with JSON content.
    """
    #parser_classes = (JSONParser,)

    #
    # TODO: Accept any type of input (just XML left to handle)
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    #

    permission_classes = (AllowAny,)
    def post(self, request):
        app = CustomApplication.objects.get(name=request.data['app_name'])

        url='http://localhost:8000/o/token/'
        headers={'Content-Type': 'application/x-www-form-urlencoded',
                 'Authorization':'Basic '+ base64_client(app.client_id,app.client_secret)}
        payload='grant_type='+request.data['grant_type']+'&username='+request.data['username']+'&password='+request.data['password']

        # check user group to assign proper scopes
            # could be get_or_404
            # could be unnecessary
        try:
            user = User.objects.get(username=request.data['username'])
        except:
            return Response("User does not exist")

        scopes = get_perms_as_urlencoded(user,app)
        payload += '&scope='+scopes
        r=requests.post(url,data=payload,headers=headers)
        a=r.json()
        a['user']= get_user_info_as_dict(user)
        scopes_for_list = get_perms(user, app)
        a['scopes_list']=get_scopes_list(scopes_for_list)


        return Response(a)

    permission_classes = (AllowAny,)

    def get(self, request):

        return render(request, 'loginform.html', {})


class RefreshView(APIView):
   # """
   # A view that can accept POST requests with JSON content.
   # """
    # parser_classes = (JSONParser,)

    #
    # TODO: Accept any type of input (just XML left to handle)
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    #

    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        # Need to call clear_expired() in order to removed expired refresh tokens from the database,
        # Otherwise expired refresh tokens will be accepted
        clear_expired()
        app = CustomApplication.objects.get(name=request.data['app_name'])

        url = 'http://localhost:8000/o/token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic ' + base64_client(app.client_id, app.client_secret)}

        payload = 'grant_type=' + request.data['grant_type'] + '&refresh_token=' + request.data['refresh_token']
        try:
            user = RefreshToken.objects.get(token=request.data['refresh_token']).user
        except:
            return Response('Invalid refresh token')
        r = requests.post(url, data=payload, headers=headers)
        a = r.json()

        a['user'] = get_user_info_as_dict(user)
        scopes_for_list = get_perms(user, app)
        a['scopes_list'] = get_scopes_list(scopes_for_list)

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
        app = CustomApplication.objects.get(name=request.data['app_name'])
        url = 'http://localhost:8000/o/revoke_token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic '+ base64_client(app.client_id,app.client_secret)}
        payload='token='+request.data['access_token']

        r = requests.post(url, data=payload, headers=headers)
        user = AccessToken.objects.get(token=request.data['access_token']).user
        all_tokens = AccessToken.objects.filter(user=user)
        print(all_tokens)
        for token in all_tokens:
            if token.application.persistent == False:
                AccessToken.delete(token=token)



        return Response("You have logged out")

class SignupView(APIView):
    def post(self, request):
        username = request.data['username']
        password = request.data['password']
        group = request.data['group']
        user = User.objects.create(username=username)
        user.set_password(password)
        user.save()

        app = CustomApplication.objects.get(name=request.data['app_name'])
        roles_init(app)
        add_group = Group.objects.get(name='{}: {}'.format(app.name,group))
        user.groups.add(add_group)

        url = 'http://localhost:8000/o/token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic ' + base64_client(app.client_id, app.client_secret)}
        payload = 'grant_type=password' + '&username=' + username + '&password=' + password

            # check user group to assign proper scopes
            # could be get_or_404
            # could be unnecessary
        try:
            user = User.objects.get(username=request.data['username'])
        except:
            return Response("User does not exist")

        scopes = get_perms_as_urlencoded(user, app)
        payload += '&scope=' + scopes
        r = requests.post(url, data=payload, headers=headers)
        a = r.json()
        a['user'] = get_user_info_as_dict(user)

        scopes_for_list = get_perms(user, app)
        a['scopes_list'] = get_scopes_list(scopes_for_list)

        return Response(a)

# simple API endpoint for frontend to check if a token is valid or not
class Validate(APIView):
    def post(self, request):
        return Response('True')


def roles_init(app):
    '''
    Create new groups for Admin and student and associates them with specified CustomApplications
    Automatically appends the CustomApplication name to the Group name 
    
    :parameter app - CustomApplication object that the Groups will be associated with
    '''
    g1 = Group.objects.get_or_create(name='%s: Admin' % app.name)[0]
    g2 = Group.objects.get_or_create(name='%s: Student' % app.name)[0]

    # ADMIN ALL GROUPS #
    assign_perm('change_Application', g1, app)  # change Application details
    assign_perm('change_registration', g1, app)  # change submission settings
    assign_perm('change_submission', g1, app)  # change registration setup
    assign_perm('view_registration_admin', g1, app)  # change registration tools
    assign_perm('add_users', g1, app)  # user create functionality
    assign_perm('write', g1, app)  # write permissions
    assign_perm('read', g1, app)  # read permissions
    assign_perm('groups', g1, app)  # groups permissions

    # STUDENT GROUPS #
    assign_perm('read', g2, app)  # read permissions
    assign_perm('super_powers', g2, app)  # super powers

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

# formats the scopes list as needed by urlencoded data
def get_perms_as_urlencoded(user,app):
    a = get_perms(user,app)
    b = ' '.join(a)
    return b


def base64_client(client_id,client_secret):
    string = client_id + ':' + client_secret
    return b64encode(string.encode('ascii')).decode('ascii')

# generates the dictionary of all scopes to be included in token JSON
def get_scopes_list(scopes):
    scopes_list = {}
    list = OAUTH2_PROVIDER['SCOPES']
    for elm in list:
        is_valid = False
        for scope in scopes:
            if elm == scope:
                is_valid = True
        scopes_list[elm] = is_valid
    return scopes_list

# generates the user info dict to be included in token JSON
def get_user_info_as_dict(user):
    user_info = {}
    user_info['id'] = user.id
    # add more to this as needed
    return user_info
