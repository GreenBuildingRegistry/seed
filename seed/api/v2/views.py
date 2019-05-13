from django.http import JsonResponse
from rest_framework import viewsets

from seed.decorators import ajax_request_class
from seed.utils.api import api_endpoint_class
from seed.utils.cache import get_cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth import get_user_model
from seed.lib.superperms.orgs.models import Organization, OrganizationUser
from seed.utils.organizations import create_organization
User = get_user_model()

import logging
_log = logging.getLogger(__name__)


class ProgressViewSetV2(viewsets.ViewSet):
    raise_exception = True

    @api_endpoint_class
    @ajax_request_class
    def retrieve(self, request, pk):
        """
        Get the progress (percent complete) for a task.

        Returns::
            {
                'progress_key': The same progress key,
                'progress': Percent completion
            }
        """
        progress_key = pk
        if get_cache(progress_key):
            return JsonResponse(get_cache(progress_key))
        else:
            return JsonResponse({
                'progress_key': progress_key,
                'progress': 0,
                'status': 'waiting'
            })


class CreateDefaultUser(APIView):

    def post(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied
        username = kwargs.get('username')
        password = kwargs.get('password')
        org_name = kwargs.get('org_name')
        user, created = User.objects.get_or_create(username=username)
        if created:
            if password:
                user.set_password(password)
            else:
                user.set_unusable_password()
            user.save()

        try:
            org = Organization.objects.get(name=org_name)
        except Organization.DoesNotExist:
            org, org_user, _ = create_organization(user, org_name)
        else:
            org_user, _ = OrganizationUser.objects.get_or_create(
                user=user, organization=org
            )

        response = {
            'status': 'success',
            'data': {
                'user': {'username': user.username, 'id': user.id},
                'organization': {'organization': org.name, 'id': org.id}
            }
        }
        return Response(response, status.HTTP_200_OK)
