from django.db import models

class Profile(models.Model):
    pub_key = models.TextField()
    username = models.CharField(max_length=64, unique=True)
    ip = models.CharField(max_length=64)
    port = models.CharField(max_length=64)

    def __str__(self):
        return self.username

