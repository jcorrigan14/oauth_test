import json
from base64 import b64encode

import requests
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.forms import modelform_factory
from django.shortcuts import render
from guardian.shortcuts import assign_perm, get_perms
from oauth2_provider.models import AccessToken, RefreshToken, clear_expired, get_application_model
from oauth2_provider.views import ReadWriteScopedResourceView, ApplicationRegistration, ApplicationUpdate, \
    ApplicationDetail, ApplicationList
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from DOT_tutorial.models import *
from DOT_tutorial.registration import NotExistException
from DOT_tutorial.serializers import UsersSerializer
from DOT_tutorial.settings import OAUTH2_PROVIDER


class LoginView(APIView):
    """
    Login Endpoint-
    This endpoint is passed a username, password, and app_name and then calls OAuth2 o/token. If the information
    is valid, a new access token is issued for the User. If invalid username, returns a 400. If invalid password,
    returns a 401.

    Utilizes a 2-legged authentication system so that POST requests with JSON and XML content can be accepted
    in addition to the default x-www-form-urlencoded data.

    POST requests need-
    Header:
        Content-Type: application/<your_data_type>

    Payload:
        username : <username>
        password : <password>
        app_name : <application_name>  
    """

    #
    # TODO: Accept any type of input (just XML left to handle)
    #       - Determine format of request.data
    #       - Properly parse and pass it as
    # TODO: change app_name to client secret?
    # TODO: there are several instances of except: which excepts ANY error. This is bad. Specify error you
    # intend on catching
    #

    permission_classes = (AllowAny,)

    def post(self, request):
        # TODO: Figure out the json.dumps() and json.loads(), its quite borked
        # TODO: Remove the entire test database feature, it was silly
        temp_data = json.dumps(request.data)
        json_data = json.loads(temp_data)
        try:
            app = CustomApplication.objects.get(name=json_data['app_name'])

        except CustomApplication.DoesNotExist:
            return Response("Application does not exist", status=status.HTTP_400_BAD_REQUEST)

        url = 'http://localhost:8000/o/token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic ' + base64_client(app.client_id, app.client_secret)}
        payload = 'grant_type=password' + '&username=' + json_data['username'] + '&password=' + \
                  json_data['password']

        try:
            genius_user = GeniusUser.objects.get(username=json_data['username'])
            print(genius_user.id)
        except GeniusUser.DoesNotExist:
            return Response("User does not exist", status=status.HTTP_400_BAD_REQUEST)

        scopes = get_perms_as_urlencoded(genius_user, app)
        print(scopes)
        payload += '&scope=' + scopes
        response = requests.post(url, data=payload, headers=headers)
        data = response.json()
        if (response.status_code == 200):
            data['user'] = get_user_info_as_dict(genius_user)
            scopes_for_list = get_perms(genius_user, app)
            data['scopes_list'] = get_scopes_list(scopes_for_list)
            try:
                data['group'] = get_groups(genius_user)
            except:
                data['group'] = {}

            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response("Not valid", status=response.status_code)

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
        try:
            app = CustomApplication.objects.get(name=request.data['app_name'])
        except CustomApplication.DoesNotExist:
            return Response("Application does not exist", status=status.HTTP_400_BAD_REQUEST)


        url = 'http://localhost:8000/o/token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic ' + base64_client(app.client_id, app.client_secret)}

        payload = 'grant_type=refresh_token' + '&refresh_token=' + request.data['refresh_token']
        try:
            user = RefreshToken.objects.get(token=request.data['refresh_token']).user
        except RefreshToken.DoesNotExist:
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
        queryset = GeniusUser.objects.all()
        serializer_class = UserSerializer(queryset, many=True)
        return Response(serializer_class.data)


# used just for testing with userView
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = GeniusUser
        fields = '__all__'


class logoutView(APIView):
    """
    Logout Endpoint-
        This endpoint calls o/revoke_token. Only mobile access tokens should be persistent. 
        When a User logs out of a web application, their tokens for all web applications will be revoked, 
        while mobile tokens will remain valid. If a user logs out of a mobile application, only the tokens
        for that specific application will be revoked, while all other tokens remain valid.

    If this flow is not working as described, check the 'Mobile Applicaiton' setting of your app in 
    the Application menu found at o/applications. 

    Utilizes a 2-legged authentication system so that POST requests with JSON and XML content can be accepted
    in addition to the default x-www-form-urlencoded data.

    POST requests need-
    Header:
        Content-Type : application/<your_data_type>
        Authorization : Bearer <access_token>

    Payload:
       token : <token>
    """

    # TODO: this script will revoke a token from a differnt app than the app_name provided.
    #  Should we prevent this?
    def post(self, request):
        try:
            app = CustomApplication.objects.get(name=request.data['app_name'])
        except CustomApplication.DoesNotExist:
            return Response("Application does not exist", status=status.HTTP_400_BAD_REQUEST)

        url = 'http://localhost:8000/o/token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic ' + base64_client(app.client_id, app.client_secret)}
        my_token = AccessToken.objects.get(token=request.data['access_token'])
        payload = 'token=' + my_token.__str__()
        user = my_token.user
        requests.post(url, data=payload, headers=headers)
        if my_token.application.persistent:
            return Response("You have logged", status=status.HTTP_200_OK)
        all_tokens = AccessToken.objects.filter(user=user)
        for token in all_tokens:
            if not token.application.persistent:
                payload = 'token=' + token.__str__()
                requests.post(url, data=payload, headers=headers)

        return Response("You have logged out", status=status.HTTP_200_OK)


class SignupView(APIView):
    """
    Signup Endpoint-
    Requires a username, password, first_name, group, and app_name. Multiple optional fileds are accepted.
    First, a new Django User is created with custom permissions based on their group. These permissions 
    determine the scope of their access token. Then, OAuth2 o/token is called to issue them an access token.

    Utilizes a 2-legged authentication system so that POST requests with JSON and XML content can be accepted
    in addition to the default x-www-form-urlencoded data.

    POST requests need-
    Header:
        Content-Type: application/<your_data_type>

    Payload:
        (Required)
        username : <username>
        password : <password>
        first_name : <first_name>
        app_name : <application_name>  
        group :    <group>  # for now Student, Teacher, or Admin
        
        (Optional)
        language : <language_id>
        salutation : <salutation_id>
        etc...
    """
    permission_classes = (AllowAny,)
    def post(self, request):
        username = request.data['username']
        try:
            GeniusUser.objects.get(username=username)
            return Response("User already exists", status=status.HTTP_403_FORBIDDEN)
        except ObjectDoesNotExist:
            pass
        password = request.data['password']
        temp_data = json.dumps(request.data)
        json_data =json.loads(temp_data)
        try:
            app = CustomApplication.objects.get(name=request.data['app_name'])
        except CustomApplication.DoesNotExist:
            return Response("Application does not exist", status=status.HTTP_400_BAD_REQUEST)
        roles_init(app)

        ## this is from old code
        myuser = None
        class_id = None
        teacher_group = UsersGroup.objects.filter(id=USERS_GROUPS_TEACHER_ID).first()
        parent_group = UsersGroup.objects.filter(id=USERS_GROUPS_PARENT_ID).first()
        if not request.user.is_anonymous():
            myuser = request.user
        ##

        try:
            with transaction.atomic():
                serializer = UsersSerializer(data=json_data)
                if serializer.is_valid():
                    serializer.save()
                    genius_user = GeniusUser.objects.get(username=username)
                    genius_user.set_password(password)
                    genius_user.save()
                else:
                    return Response("Invalid user data", status=status.HTTP_400_BAD_REQUEST)
                if 'class_id' in request.data:
                    class_id = int(request.data['class_id'])
        except NotExistException as ex:
            return Response({'error': '{}'.format(ex.list)}, status=status.HTTP_406_NOT_ACCEPTABLE)
        except Exception as ex:
            return Response({'error': ex.args[0]}, status=status.HTTP_400_BAD_REQUEST)


        group = Group.objects.get(name='{}: {}'.format(app.name, request.data['group']))
        genius_user.groups.add(group)

        url = 'http://localhost:8000/o/token/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': 'Basic ' + base64_client(app.client_id, app.client_secret)}
        payload = 'grant_type=password' + '&username=' + username + '&password=' + password
        scopes = get_perms_as_urlencoded(genius_user, app)
        payload += '&scope=' + scopes
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code != 200:
            return Response("Invalid credentials", status=response.status_code)
        data = response.json()
        data['user'] = get_user_info_as_dict(genius_user)
        scopes_for_list = get_perms(genius_user, app)
        data['scopes_list'] = get_scopes_list(scopes_for_list)
        try:
            data['group'] = get_groups(genius_user)
        except:
            data['group'] = {}
        return Response(data, status=status.HTTP_200_OK)



class Validate(APIView):
    """
        Validate Endpoint-
        A simple API endpoint for frontend to check if a token is valid or not. Will return 200 and 'True'
        or 400 Response. 

        POST requests need-
        Header:
            Authorization : Bearer <access_token>
    """

    def post(self, request):
        return Response('True')


def roles_init(app):
    """
    Create new groups for Principal, Teacher, and Student and associates them with specified CustomApplications.
    Automatically appends the CustomApplication name to the Group name 

    :parameter app - CustomApplication object that the Groups will be associated with
    """
    principal_group = Group.objects.get_or_create(name='%s: Principal' % app.name)[0]
    student_group = Group.objects.get_or_create(name='%s: Student' % app.name)[0]
    teacher_group = Group.objects.get_or_create(name='%s: Teacher' % app.name)[0]


    # PRINCIPAL GROUPS #
    assign_perm('change_Application', principal_group, app)
    assign_perm('change_registration', principal_group, app)
    assign_perm('change_submission', principal_group, app)
    assign_perm('view_registration_admin', principal_group, app)
    assign_perm('add_users', principal_group, app)
    assign_perm('write', principal_group, app)
    assign_perm('read', principal_group, app)
    assign_perm('groups', principal_group, app)

    # TEACHER GROUPS #
    assign_perm('change_registration', teacher_group, app)
    assign_perm('change_submission', teacher_group, app)
    assign_perm('view_registration_admin', teacher_group, app)
    assign_perm('add_users', teacher_group, app)
    assign_perm('write', teacher_group, app)
    assign_perm('read', teacher_group, app)
    assign_perm('groups', teacher_group, app)

    # STUDENT GROUPS #
    # assign_perm('read', student_group, app)
    assign_perm('super_powers', student_group, app)
    assign_perm('write', student_group, app)
    assign_perm('read', student_group, app)


    return True


def get_perms_as_urlencoded(user, app):
    """
    Formats the scopes list as needed for urlencoded data
    :param user: Django User object
    :param app: CustomApplication object
    :return: All user permissions in the formatting required by urlencoded data type
    """
    perms = get_perms(user, app)
    perms_formatted = ' '.join(perms)
    return perms_formatted


def base64_client(client_id, client_secret):
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

def get_groups(genius_user):
    """
    used to add group to JSON token response
    :param genius_user: GeniusUSer Object
    :return: formatted group name
    """
    group = genius_user.groups.values('name')
    return group[0]['name']

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

    template_name = "custom_application_registration.html"


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

    template_name = "custom_application_form.html"


class CustomApplicationDetail(ApplicationDetail):
    """
    Points the ApplicationDetail page to custom html that includes Persistent field
    """
    template_name = "custom_application_detail.html"


class CustomApplicationList(ApplicationList):
    template_name = "custom_application_list.html"

