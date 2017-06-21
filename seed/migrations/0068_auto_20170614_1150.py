# -*- coding: utf-8 -*-
# Generated by Django 1.9.13 on 2017-06-14 18:50
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('seed', '0067_auto_20170602_0740'),
    ]

    operations = [
        migrations.AlterIndexTogether(
            name='propertystate',
            index_together=set([('import_file', 'data_state')]),
        ),
        migrations.AlterIndexTogether(
            name='propertyview',
            index_together=set([('state', 'cycle')]),
        ),
        migrations.AlterIndexTogether(
            name='taxlotproperty',
            index_together=set([('cycle', 'property_view'), ('cycle', 'taxlot_view'), ('property_view', 'taxlot_view')]),
        ),
        migrations.AlterIndexTogether(
            name='taxlotstate',
            index_together=set([('import_file', 'data_state')]),
        ),
        migrations.AlterIndexTogether(
            name='taxlotview',
            index_together=set([('state', 'cycle')]),
        ),
    ]
