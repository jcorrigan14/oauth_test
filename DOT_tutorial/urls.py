from django.conf.urls import url, include
from django.contrib.auth.models import User, Group
from django.contrib import admin
admin.autodiscover()

from rest_framework import permissions, routers, serializers, viewsets

from oauth2_provider.ext.rest_framework import TokenHasReadWriteScope, TokenHasScope


# first we define the serializers
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group


# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    queryset = User.objects.all()
    serializer_class = UserSerializer


class GroupViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


# Routers provide an easy way of automatically determining the URL conf
router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'groups', GroupViewSet)


# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browseable API.
urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    url(r'^admin/', admin.site.urls),
]


"""
Q3aRJ4ohlJUa9yQX1r502JqCpzRd2W3EJwV8RFG4
zqtupaWrpO0lg1moH6pNfQ6VGd2FEkjCbX0jluXpFImJcdDJMMc50nBFDyZJq2sbazxoQ4tVFT71h6P4DSwZeD6JTPxuYaJ4Bc4HT9lantCn2JmPcKTRxDSqu3XIZtCV


FLzftpqgxLPEpbmlg7UjiOQku3rwEP
A1TDQM8F8fKDzQ6pIRJVmAjqAhNHPE

pNWXw8GFqiGQ2moQkhT2020hlKyL3a
vs91qwMihRpcPSsS3bBBiGAYV6PJq3

"""