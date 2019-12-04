# Generated by Django 2.2.7 on 2019-12-01 18:39

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pub_key', models.TextField()),
                ('priv_key', models.TextField()),
                ('username', models.CharField(max_length=64)),
                ('ip', models.CharField(max_length=64)),
                ('port', models.CharField(max_length=64)),
            ],
        ),
    ]
