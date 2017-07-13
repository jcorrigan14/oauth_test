from base64 import b64encode

import requests

from django.contrib.auth.models import User
from django.forms import modelform_factory
from django.shortcuts import render

from guardian.shortcuts import assign_perm, get_perms
from oauth2_provider.models import AccessToken, RefreshToken, clear_expired, get_application_model
from oauth2_provider.views import ReadWriteScopedResourceView, ApplicationRegistration, ApplicationUpdate, \
    ApplicationDetail

from rest_framework import serializers,status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from DOT_tutorial.settings import OAUTH2_PROVIDER
from DOT_tutorial.models import *


class LoginView(APIView):
    """
    Login Endpoint-
    This endpoint is passed a username, password, and app_name and then calls OAuth2 o/token. If the information
    is valid, a new access token is issued for the User. If invalid username, returns a 404. If invalid password,
    returns a 401.
    
    Utilizes a 2-legged authentication system so that POST requests with JSON and XML content can be accepted
    in addition to the default x-www-form-urlencoded data.
    
    POST requests need-
    Header:
        Content-Type: application/<your_data_type>
    
    Payload:
        grant_type : "password"
        username : <username>
        password : <password>
        app_name : <application_name>  
    """

    #
    # TODO: Accept any type of input (just XML left to handle)
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    # TODO: change app_name to client secret?
    #

    permission_classes = (AllowAny,)
    def post(self, request):
        app = CustomApplication.objects.get(name=request.data['app_name'])

        url='http://localhost:8000/o/token/'
        headers={'Content-Type': 'application/x-www-form-urlencoded',
                 'Authorization':'Basic '+ base64_client(app.client_id,app.client_secret)}
        payload='grant_type='+request.data['grant_type']+'&username='+request.data['username']+'&password='+request.data['password']

        try:
            user = User.objects.get(username=request.data['username'])
        except:
            return Response("User does not exist",status=status.HTTP_404_NOT_FOUND)

        scopes = get_perms_as_urlencoded(user,app)
        payload += '&scope='+scopes
        response=requests.post(url,data=payload,headers=headers)
        data=response.json()
        if(response.status_code==200):
            data['user']= get_user_info_as_dict(user)
            scopes_for_list = get_perms(user, app)
            data['scopes_list']=get_scopes_list(scopes_for_list)

            return Response(data,status=status.HTTP_200_OK)
        else:
            return Response("Not valid",status=status.HTTP_401_UNAUTHORIZED)

    permission_classes = (AllowAny,)

    def get(self, request):
        return render(request, 'loginform.html', {})


class RefreshView(APIView):
    """
    Refresh Endpoint-
        This endpoint should be called when a request to /valid attempts to use an expired access token. 
        This endpoint is passed a refresh token and calls OAuth2 o/token. If the refresh token is valid, 
        a new access token is issued for the User and the old refresh token is revoked. If the refresh token
        is invalid or expired, it returns a 401.
    
    Utilizes a 2-legged authentication system so that POST requests with JSON and XML content can be accepted
    in addition to the default x-www-form-urlencoded data.

    POST requests need-
    Header:
        Content-Type: application/<your_data_type>

    Payload:
        grant_type : "refresh_token"
        refresh_token : <refresh_token>
        app_name : <application_name>  
    """

    #
    # TODO: Accept any type of input (just XML left to handle)
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    # TODO: change app_name to client secret?
    #

    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        # We call clear_expired() here in order to removed expired refresh tokens from the database before
        # making the call to o/token, otherwise expired refresh tokens would be accepted
        clear_expired()
        app = CustomApplication.objects.get(name=request.data['app_name'])

        url = 'http://localhost:8000/o/token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic ' + base64_client(app.client_id, app.client_secret)}

        payload = 'grant_type=' + request.data['grant_type'] + '&refresh_token=' + request.data['refresh_token']
        try:
            user = RefreshToken.objects.get(token=request.data['refresh_token']).user
        except:
            return Response('Invalid refresh token', status=status.HTTP_401_UNAUTHORIZED)
        response = requests.post(url, data=payload, headers=headers)
        data = response.json()

        data['user'] = get_user_info_as_dict(user)
        scopes_for_list = get_perms(user, app)
        data['scopes_list'] = get_scopes_list(scopes_for_list)

        return Response(data)

#
# All views that don't specify "permission_classes = (AllowAny,)" are Authentication protected and therefore
#  must be passed a valid access token in the header in order to grant access to the endpoint
#       i.e. header='Authorization=Bearer <access_token>'
#
class userView(ReadWriteScopedResourceView, APIView):
    """
    User Endpoint-
        A custom endpoint that is Authentication protected. A valid access token is required to access
        this endpoint. For testing purposes only. 
 
    POST requests need-
    Header:
        Authorization : "Bearer <access_token>"
    """
    required_scopes = ['groups']
    def post(self, request):
        queryset = User.objects.all()
        serializer_class = UserSerializer(queryset,many=True)
        return Response(serializer_class.data)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class logoutView(APIView):
    """
    Logout Endpoint-
        This endpoint is called when a User logs out and calls o/revoke_token accordingly. 
        Only mobile access tokens should be persistent. When a User logs out of a web application, 
        their tokens for all web applications will be revoked, while mobile tokens will remain valid. 
        If a user logs out of a mobile application, only the tokens for that specific application will be
        revoked, while all other tokens remain valid.
        
    If this flow is not working as described, check the 'Persistent' setting of your app in the Application 
    menu found at o/applications. 
    
    Utilizes a 2-legged authentication system so that POST requests with JSON and XML content can be accepted
    in addition to the default x-www-form-urlencoded data.

    POST requests need-
    Header:
        Content-Type : application/<your_data_type>
        Authorization : Bearer <access_token>

    Payload:
       token : <token>
    """
    def post(self, request):
        is_mobile = False
        app = CustomApplication.objects.get(name=request.data['app_name'])
        url = 'http://localhost:8000/o/revoke_token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic '+ base64_client(app.client_id,app.client_secret)}
        my_token = AccessToken.objects.get(token=request.data['access_token'])
        if my_token.persistent == True:
            is_mobile = True
        payload = 'token=' + my_token.__str__()
        user = my_token.user
        requests.post(url, data=payload, headers=headers)
        if is_mobile == True:
            return Response("You have logged out", status=status.HTTP_200_OK)
        all_tokens = AccessToken.objects.filter(user=user)
        for token in all_tokens:
            if token.application.persistent == False:
                payload = 'token=' + token.__str__()
                requests.post(url, data=payload, headers=headers)

        return Response("You have logged out",status=status.HTTP_200_OK)

class SignupView(APIView):
    """
    Signup Endpoint-
    This endpoint is passed a username, password, group, and app_name. First, a new Django User is created 
    with custom permissions based on their group. These permissions determine the scope of their access
    token. Then, OAuth2 o/token is called to issue them an access token.

    Utilizes a 2-legged authentication system so that POST requests with JSON and XML content can be accepted
    in addition to the default x-www-form-urlencoded data.

    POST requests need-
    Header:
        Content-Type: application/<your_data_type>

    Payload:
        username : <username>
        password : <password>
        app_name : <application_name>  
        group : <group>  # for now Student or Admin
    """
    permission_classes = (AllowAny,)
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
        scopes = get_perms_as_urlencoded(user, app)
        payload += '&scope=' + scopes
        response = requests.post(url, data=payload, headers=headers)
        data = response.json()
        data['user'] = get_user_info_as_dict(user)
        scopes_for_list = get_perms(user, app)
        data['scopes_list'] = get_scopes_list(scopes_for_list)

        return Response(data,status=status.HTTP_200_OK)

#
class Validate(APIView):
    """
        Validate Endpoint-
        API endpoint for frontend to check if a token is valid or not
        
        POST requests need-
        Header:
            Authorization : Bearer <access_token>
    """
    def post(self, request):
        return Response('True')


def roles_init(app):
    """
    Create new groups for Admin and Student and associates them with specified CustomApplications
    Automatically appends the CustomApplication name to the Group name 
    
    :parameter app - CustomApplication object that the Groups will be associated with
    """
    admin_group = Group.objects.get_or_create(name='%s: Admin' % app.name)[0]
    student_group = Group.objects.get_or_create(name='%s: Student' % app.name)[0]

    # ADMIN ALL GROUPS #
    assign_perm('change_Application', admin_group, app)
    assign_perm('change_registration', admin_group, app)
    assign_perm('change_submission', admin_group, app)
    assign_perm('view_registration_admin', admin_group, app)
    assign_perm('add_users', admin_group, app)
    assign_perm('write', admin_group, app)
    assign_perm('read', admin_group, app)
    assign_perm('groups', admin_group, app)

    # STUDENT GROUPS #
    # assign_perm('read', student_group, app)
    assign_perm('super_powers', student_group, app)

    ApplicationGroup.objects.get_or_create(group=admin_group, application=app)
    ApplicationGroup.objects.get_or_create(group=student_group, application=app)

    return True


def user_roles(user):
    """
    Return a list of all the Groups for a User for all CustomApplications
    :param user: Django User object  
    :return group_list: A list of Groups for the passed User
    """
    try:
        all_groups = Group.objects.filter(user=user)
        group_list = []

        for group in all_groups:
            if ApplicationGroup.objects.filter(group=group).exists():
                application_group = ApplicationGroup.objects.get(group=group)
                group_list.append(application_group)
    except:
        group_list = []

    return {'USER_GROUPS': group_list}


def get_perms_as_urlencoded(user,app):
    """
    formats the scopes list as needed by urlencoded data
    :param user: Django User object
    :param app: CustomApplication object
    :return: All user permissions in the formatting required by urlencoded data type
    """
    perms = get_perms(user,app)
    perms_formatted = ' '.join(perms)
    return perms_formatted


def base64_client(client_id,client_secret):
    """
    Base64 encodes the client ID and client secret at runtime for Authorization header
    :param client_id 
    :param client_secret 
    :return: formatted string
    """
    string = client_id + ':' + client_secret
    return b64encode(string.encode('ascii')).decode('ascii')


def get_scopes_list(scopes):
    """
    Generates the dictionary of all scopes to be included in the custom access token response JSON
    :param scopes: list of all possible scoped 
    :return: formatted dict of scopes stating True/False for each
    """
    scopes_list = {}
    list = OAUTH2_PROVIDER['SCOPES']
    for elm in list:
        is_valid = False
        for scope in scopes:
            if elm == scope:
                is_valid = True
        scopes_list[elm] = is_valid
    return scopes_list


def get_user_info_as_dict(user):
    """
    Generates the user info dict to be included in token JSON
    :param user: Django User object 
    :return: a dict of user information to be used by frontend
    """
    user_info = {}
    user_info['id'] = user.id
    # add more to this as needed
    return user_info

class CustomApplicationRegistration(ApplicationRegistration):
    def get_form_class(self):
        """
        Extends the ApplicationRegistration page to include Persistent field
        """
        return modelform_factory(
            get_application_model(),
            fields=('name', 'client_id', 'client_secret', 'client_type',
                    'authorization_grant_type', 'redirect_uris', 'persistent')
        )

class CustomApplicationUpdate(ApplicationUpdate):
    def get_form_class(self):
        """
        Extends the ApplicationUpdate page to include Persistent field
        """
        return modelform_factory(
            get_application_model(),
            fields=('name', 'client_id', 'client_secret', 'client_type',
                    'authorization_grant_type', 'redirect_uris', 'persistent')
        )

class CustomApplicationDetail(ApplicationDetail):
    """
    Points the ApplicationDetail page to custom html that includes Persistent field
    """
    template_name = "custom_application_detail.html"