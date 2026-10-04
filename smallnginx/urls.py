from django.urls import path
from panel import views

urlpatterns = [
    path('', views.index),
    path('login/', views.sign_in),
    path('logout/', views.sign_out),
    path('api/<str:resource>/', views.api),
]