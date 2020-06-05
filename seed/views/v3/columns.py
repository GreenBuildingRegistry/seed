# !/usr/bin/env python
# encoding: utf-8
"""
:copyright (c) 2014 - 2020, The Regents of the University of California, through Lawrence Berkeley National Laboratory (subject to receipt of any required approvals from the U.S. Department of Energy) and contributors. All rights reserved.  # NOQA
:author
"""
import logging
from django.http import JsonResponse
from rest_framework import status
from rest_framework.parsers import JSONParser, FormParser
from rest_framework.renderers import JSONRenderer
from seed.decorators import ajax_request_class
from seed.lib.superperms.orgs.decorators import has_perm_class
from rest_framework.decorators import action
from seed.models.columns import Column
from seed.serializers.columns import ColumnSerializer
from seed.utils.api import OrgValidateMixin, OrgCreateUpdateMixin
from seed.utils.viewsets import SEEDOrgNoPatchOrOrgCreateModelViewSet
from seed.utils.api_schema import AutoSchemaHelper

_log = logging.getLogger(__name__)


class ColumnSchema(AutoSchemaHelper):
    def __init__(self, *args):
        super().__init__(*args)

        self.manual_fields = {
            ('GET', 'list'): [
                self.org_id_field(),
                self.query_string_field(
                    name='inventory_type',
                    required=False,
                    description='Which inventory type is being matched (for related fields and naming)'
                                '\nDefault: "property"'
                ),
                self.query_boolean_field(
                    name='used_only',
                    required=False,
                    description='Determine whether or not to show only the used fields '
                                '(i.e. only columns that have been mapped)'
                                '\nDefault: "false"'
                ),
            ],
            ('POST', 'create'): [self.org_id_field(required=False)],
            ('GET', 'retrieve'): [self.org_id_field()],
            ('DELETE', 'delete'): [self.org_id_field()],
            ('POST', 'rename'): [
                self.body_field(
                    name='data',
                    required=True,
                    description="rename columns",
                    params_to_formats={
                        'new_column_name': 'string',
                        'overwrite': 'boolean'
                    }
                )
            ]
        }

        self.overwrite_params.extend([('POST', 'rename')])


class ColumnViewSet(OrgValidateMixin, SEEDOrgNoPatchOrOrgCreateModelViewSet, OrgCreateUpdateMixin):
    """
    create:
        Create a new Column within a specified org or user's currently activated org.
    update:
        Update a column and modify which dataset it belongs to.
    delete:
        Deletes a single column.
    """
    raise_exception = True
    serializer_class = ColumnSerializer
    renderer_classes = (JSONRenderer,)
    model = Column
    pagination_class = None
    parser_classes = (JSONParser, FormParser)
    swagger_schema = ColumnSchema

    def get_queryset(self):
        # check if the request is properties or taxlots
        org_id = self.get_organization(self.request)
        return Column.objects.filter(organization_id=org_id)

    @ajax_request_class
    def list(self, request):
        """
        Retrieves all columns for the user's organization including the raw database columns. Will
        return all the columns across both the Property and Tax Lot tables. The related field will
        be true if the column came from the other table that is not the 'inventory_type' (which
        defaults to Property)
        ___
        parameters:
           - name: organization_id
             description: The organization_id for this user's organization
             required: true
             paramType: query
           - name: inventory_type
             description: Which inventory type is being matched (for related fields and naming).
               property or taxlot
             required: false
             paramType: query
           - name: used_only
             description: Determine whether or not to show only the used fields (i.e. only columns that have been mapped)
             type: boolean
             required: false
             paramType: query
        type:
           status:
               required: true
               type: string
               description: Either success or error
           columns:
               required: true
               type: array[column]
               description: Returns an array where each item is a full column structure.
        """
        organization_id = self.get_organization(self.request)
        inventory_type = request.query_params.get('inventory_type', 'property')
        only_used = request.query_params.get('only_used', False)
        columns = Column.retrieve_all(organization_id, inventory_type, only_used)
        return JsonResponse({
            'status': 'success',
            'columns': columns,
        })

    @ajax_request_class
    def retrieve(self, request, pk=None):
        """
        This API endpoint retrieves a Column
        ---
        parameters:
            - name: organization_id
              description: Organization ID
              type: integer
              required: true
        type:
            status:
                type: string
                description: success or error
                required: true
            column:
                required: true
                type: dictionary
                description: Returns a dictionary of a full column structure with keys such as
                             keys ''name'', ''id'', ''is_extra_data'', ''column_name'',
                             ''table_name'',..
        """
        organization_id = self.get_organization(self.request)
        # check if column exists for the organization
        try:
            c = Column.objects.get(pk=pk)
        except Column.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'column with id {} does not exist'.format(pk)
            }, status=status.HTTP_404_NOT_FOUND)

        if c.organization.id != organization_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Organization ID mismatch between column and organization'
            }, status=status.HTTP_400_BAD_REQUEST)

        return JsonResponse({
            'status': 'success',
            'column': ColumnSerializer(c).data
        })

    @ajax_request_class
    @has_perm_class('can_modify_data')
    @action(detail=True, methods=['POST'])
    def rename(self, request, pk=None):
        """
        This API endpoint renames a Column
        ---
        """
        org_id = self.get_organization(request)
        try:
            column = Column.objects.get(id=pk, organization_id=org_id)
        except Column.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'Cannot find column in org=%s with pk=%s' % (org_id, pk)
            }, status=status.HTTP_404_NOT_FOUND)

        new_column_name = request.data.get('new_column_name', None)
        overwrite = request.data.get('overwrite', False)
        if not new_column_name:
            return JsonResponse({
                'success': False,
                'message': 'You must specify the name of the new column as "new_column_name"'
            }, status=status.HTTP_400_BAD_REQUEST)

        result = column.rename_column(new_column_name, overwrite)
        if not result[0]:
            return JsonResponse({
                'success': False,
                'message': 'Unable to rename column with message: "%s"' % result[1]
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return JsonResponse({
                'success': True,
                'message': result[1]
            })