# Generated by Django 4.0.3 on 2022-05-06 04:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registration', '0008_alter_user_role_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role_code',
            field=models.CharField(max_length=255),
        ),
    ]
