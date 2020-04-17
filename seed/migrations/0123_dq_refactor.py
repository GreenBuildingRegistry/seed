# Generated by Django 2.2.10 on 2020-04-13 23:03

from django.db import migrations, models


def forwards(apps, schema_editor):
    Rule = apps.get_model('seed', 'Rule')

    Rule.objects.filter(min=None, max=None, required=True).update(condition='required')
    Rule.objects.filter(min=None, max=None, required=False).update(condition='not_null')
    Rule.objects.exclude(min=None, max=None).filter(data_type=1).update(condition='include')
    Rule.objects.exclude(min=None, max=None).exclude(data_type=1).update(condition='range')


class Migration(migrations.Migration):

    dependencies = [
        ('seed', '0122_auto_20200303_1428'),
    ]

    operations = [
        migrations.AddField(
            model_name='rule',
            name='condition',
            field=models.CharField(blank=True, default='', max_length=200),
        ),

        migrations.RunPython(forwards),
    ]
