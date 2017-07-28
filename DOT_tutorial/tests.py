from datetime import timedelta

from django.utils import timezone
from rest_framework.test import APITestCase, APIRequestFactory, force_authenticate

from .views import *


class LoginTests(APITestCase):
    """
    Testing with OAuth2 is difficult because calls to /o/token will always point to the live(production)
     databse. I have yet to find a solution to point /o/token to the temporary testing databse.
     
     You can hardcode data that exists in the live(production) database and tests will pass, but 
     this is terrible convention. Production data should not be read in tests, and especially should
      not be written to (such as in the case of /signup/ )
     
     Use the APIRequestFactory to make API calls that point to the temporary testing database
        - The issue is that when these calls hit o/token they escape to the production database
    Else, ignore the factory and make API calls as you would in the views.py file with hardcoded production 
    data (bad practice)
    
    Server has to be running for these tests to work
    """
    # TODO: Currently all the tests have hardcoded production data (not good, needs fix)
    def setUp(self):
        self.factory = APIRequestFactory()

        # first create a superuser
        admin = GeniusUser.objects.create_user('admin', password='qwerty123')
        admin.is_superuser = True
        admin.is_staff = True
        admin.save()

        app = CustomApplication.objects.create(name='Test1',
                                               persistent=False,
                                               client_type='confidential',
                                               authorization_grant_type='password',
                                               user=admin)

        access_token = AccessToken.objects.create(
            user=admin,
            scope='read write',
            expires=timezone.now() + timedelta(seconds=300),
            token='secret-access-token-key',
            application=app
        )




    def test_valid_login_json(self):
        #
        # In order for this test to pass, there must be a admin user with the password qwerty123
        # who is registered to an application called app1
        #
        url = 'http://localhost:8000/login/'
        headers = {'Content_Type' : 'application/json'}
        payload = {
            "username":"admin",
            "password":"qwerty123",
            "app_name":"app1"
        }
        #request = self.factory.post(url, data=payload, format='json')
        response = requests.post(url, data=payload, headers=headers)

        # response = LoginView.as_view()(response)

        self.assertIs(response.status_code == 200, True)

    def test_valid_login_urlencoded(self):
        url = 'http://localhost:8000/login/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        payload = 'username=admin&password=qwerty123&app_name=app1'
        response = requests.post(url, data=payload, headers=headers)
        self.assertIs(response.status_code == 200, True)

    def test_invalid_login_urlencoded(self):
        url = 'http://localhost:8000/login/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        payload = 'username=NOTAREALSUER&password=qwerty123&app_name=app1'
        response = requests.post(url, data=payload, headers=headers)
        self.assertIs(response.status_code == 400, True)

    def test_validation_pass(self):
        # url = 'http://localhost:8000/valid/'
        # headers = {'Authorization': 'Bearer wUuUXEOzY2T6jgPyIbTf94ZBdOlKav'}
        #
        # #payload = 'username=admin&password=qwerty123&app_name=app1'
        # response = requests.post(url, headers=headers)
        # self.assertIs(response.status_code == 200, True)
        url = '/valid/'
        token = AccessToken.objects.get(pk=1)
        user = GeniusUser.objects.get(pk=2)
        request = self.factory.post(url)
        force_authenticate(request, user=user, token=token)
        response = Validate.as_view()(request)
        self.assertIs(response.status_code == 200, True)

    def test_validation_fail(self):
        url = '/valid/'
        token = AccessToken.objects.get(pk=1)
        user = GeniusUser.objects.get(pk=2)
        request = self.factory.post(url)
        # force_authenticate(request, user=user, token=token) remove this line, should fail with 401 response
        response = Validate.as_view()(request)
        self.assertIs(response.status_code == 401, True)

    def test_valid_signup(self):
        """
        Ensure we can create a new user.
        Broken! Creates a user successfully but after, when trying to access o/token to log them in, 
        it searches the production db and therefore the app credentials are not valid
        """


        factory = APIRequestFactory()

        request = factory.post('/signup/?test=true', {
            "app_name":"Test1",
            "username":"DjangoTestUser1",
            "password":"qwerty123",
            "first_name":"Johnny",
            "last_name":"Hopkins",
            "email":"test@test.com",
            "group":"Student"
        },
                               format='json'
                               )
        # url = 'http://localhost:8000/signup/?test=true'
        # headers = {'Content-Type': ='application/json'}
        # payload =

        # response = request.post(url, data=json.dumps(payload), headers=headers)
        response = SignupView.as_view()(request)
        self.assertIs(response.status_code == 200, True)
        test_user = GeniusUser.objects.using('test').get(username='DjangoTestUser1')
        test_user.delete()
        # self.assertEqual(GeniusUser.objects.using('test').get(username='DjangoTestUser1'), None)
        with self.assertRaises(GeniusUser.DoesNotExist):
            GeniusUser.objects.using('test').get(username='DjangoTestUser1')