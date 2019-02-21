# -*- coding: utf-8 -*-
# Generated by Django 1.11.16 on 2018-11-21 21:02
from __future__ import unicode_literals

import django.contrib.gis.db.models.fields
from django.db import migrations, models


def forwards(apps, schema_editor):
    Column = apps.get_model("seed", "Column")
    Organization = apps.get_model("orgs", "Organization")

    new_db_fields = [
        {
            'column_name': 'geocoding_confidence',
            'table_name': 'PropertyState',
            'display_name': 'Geocoding Confidence',
            'data_type': 'string',
        }, {
            'column_name': 'geocoding_confidence',
            'table_name': 'TaxLotState',
            'display_name': 'Geocoding Confidence',
            'data_type': 'string',
        }
    ]

    # Go through all the organizatoins
    for org in Organization.objects.all():
        for new_db_field in new_db_fields:
            columns = Column.objects.filter(
                organization_id=org.id,
                table_name=new_db_field['table_name'],
                column_name=new_db_field['column_name'],
                is_extra_data=False,
            )

            if not columns.count():
                new_db_field['organization_id'] = org.id
                Column.objects.create(**new_db_field)
            elif columns.count() == 1:
                # If the column exists, then just update the display_name and data_type if empty
                c = columns.first()
                if c.display_name is None or c.display_name == '':
                    c.display_name = new_db_field['display_name']
                if c.data_type is None or c.data_type == '' or c.data_type == 'None':
                    c.data_type = new_db_field['data_type']
                c.save()
            else:
                print("  More than one column returned")


class Migration(migrations.Migration):
    dependencies = [
        ('seed', '0097_auto_20181107_1231'),
    ]

    operations = [
        migrations.AddField(
            model_name='propertystate',
            name='long_lat',
            field=django.contrib.gis.db.models.fields.PointField(blank=True, geography=True, null=True, srid=4326),
        ),
        migrations.AddField(
            model_name='taxlotstate',
            name='long_lat',
            field=django.contrib.gis.db.models.fields.PointField(blank=True, geography=True, null=True, srid=4326),
        ),
        migrations.AddField(
            model_name='propertystate',
            name='geocoding_confidence',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AddField(
            model_name='taxlotstate',
            name='geocoding_confidence',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AddField(
            model_name='propertystate',
            name='bounding_box',
            field=django.contrib.gis.db.models.fields.PolygonField(blank=True, geography=True, null=True, srid=4326),
        ),
        migrations.AddField(
            model_name='taxlotstate',
            name='bounding_box',
            field=django.contrib.gis.db.models.fields.PolygonField(blank=True, geography=True, null=True, srid=4326),
        ),
        migrations.AddField(
            model_name='propertystate',
            name='centroid',
            field=django.contrib.gis.db.models.fields.PolygonField(blank=True, geography=True, null=True, srid=4326),
        ),
        migrations.RunPython(forwards),
    ]