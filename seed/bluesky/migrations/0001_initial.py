# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-05-26 19:13
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django_pgjson.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('orgs', '0003_auto_20160412_1123'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Cycle',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('start', models.DateTimeField()),
                ('end', models.DateTimeField()),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='orgs.Organization')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Property',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('campus', models.BooleanField(default=False)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='orgs.Organization')),
                ('parent_property', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='bluesky.Property')),
            ],
            options={
                'verbose_name_plural': 'properties',
            },
        ),
        migrations.CreateModel(
            name='PropertyState',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('confidence', models.FloatField(default=0)),
                ('jurisdiction_property_identifier', models.CharField(blank=True, max_length=255, null=True)),
                ('lot_number', models.CharField(blank=True, max_length=255, null=True)),
                ('property_name', models.CharField(blank=True, max_length=255, null=True)),
                ('address_line_1', models.CharField(blank=True, max_length=255, null=True)),
                ('address_line_2', models.CharField(blank=True, max_length=255, null=True)),
                ('city', models.CharField(blank=True, max_length=255, null=True)),
                ('state', models.CharField(blank=True, max_length=255, null=True)),
                ('postal_code', models.CharField(blank=True, max_length=255, null=True)),
                ('building_count', models.IntegerField(blank=True, null=True)),
                ('property_notes', models.TextField(blank=True, null=True)),
                ('use_description', models.CharField(blank=True, max_length=255, null=True)),
                ('gross_floor_area', models.FloatField(blank=True, null=True)),
                ('year_built', models.IntegerField(blank=True, null=True)),
                ('recent_sale_date', models.DateTimeField(blank=True, null=True)),
                ('conditioned_floor_area', models.FloatField(blank=True, null=True)),
                ('occupied_floor_area', models.FloatField(blank=True, null=True)),
                ('owner', models.CharField(blank=True, max_length=255, null=True)),
                ('owner_email', models.CharField(blank=True, max_length=255, null=True)),
                ('owner_telephone', models.CharField(blank=True, max_length=255, null=True)),
                ('owner_address', models.CharField(blank=True, max_length=255, null=True)),
                ('owner_city_state', models.CharField(blank=True, max_length=255, null=True)),
                ('owner_postal_code', models.CharField(blank=True, max_length=255, null=True)),
                ('building_portfolio_manager_identifier', models.CharField(blank=True, max_length=255, null=True)),
                ('building_home_energy_saver_identifier', models.CharField(blank=True, max_length=255, null=True)),
                ('energy_score', models.IntegerField(blank=True, null=True)),
                ('site_eui', models.FloatField(blank=True, null=True)),
                ('generation_date', models.DateTimeField(blank=True, null=True)),
                ('release_date', models.DateTimeField(blank=True, null=True)),
                ('site_eui_weather_normalized', models.FloatField(blank=True, null=True)),
                ('source_eui', models.FloatField(blank=True, null=True)),
                ('energy_alerts', models.TextField(blank=True, null=True)),
                ('space_alerts', models.TextField(blank=True, null=True)),
                ('building_certification', models.CharField(blank=True, max_length=255, null=True)),
                ('extra_data', django_pgjson.fields.JsonField(default={})),
            ],
        ),
        migrations.CreateModel(
            name='PropertyView',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cycle', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bluesky.Cycle')),
                ('property', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='views', to='bluesky.Property')),
                ('state', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bluesky.PropertyState')),
            ],
        ),
        migrations.CreateModel(
            name='TaxLot',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='orgs.Organization')),
            ],
        ),
        migrations.CreateModel(
            name='TaxLotProperty',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('primary', models.BooleanField(default=True)),
                ('cycle', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bluesky.Cycle')),
                ('property_view', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bluesky.PropertyView')),
            ],
        ),
        migrations.CreateModel(
            name='TaxLotState',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('confidence', models.FloatField(default=0)),
                ('jurisdiction_taxlot_identifiers', models.CharField(blank=True, max_length=255, null=True)),
                ('block_number', models.CharField(blank=True, max_length=255, null=True)),
                ('district', models.CharField(blank=True, max_length=255, null=True)),
                ('address', models.CharField(blank=True, max_length=255, null=True)),
                ('city', models.CharField(blank=True, max_length=255, null=True)),
                ('state', models.CharField(blank=True, max_length=255, null=True)),
                ('postal_code', models.CharField(blank=True, max_length=255, null=True)),
                ('number_properties', models.IntegerField(blank=True, null=True)),
                ('extra_data', django_pgjson.fields.JsonField(default={})),
            ],
        ),
        migrations.CreateModel(
            name='TaxLotView',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cycle', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bluesky.Cycle')),
                ('state', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bluesky.TaxLotState')),
                ('taxlot', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='views', to='bluesky.TaxLot')),
            ],
        ),
        migrations.AddField(
            model_name='taxlotproperty',
            name='taxlot_view',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bluesky.TaxLotView'),
        ),
    ]