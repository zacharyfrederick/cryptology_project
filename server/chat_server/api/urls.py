

from django.urls import path
from . import views

urlpatterns = [
    path('register', views.RegisterView.as_view()),
    path('create_chat', views.StartChatView.as_view()),
]