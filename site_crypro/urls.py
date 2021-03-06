"""site_crypro URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from crypto import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('RSA/', views.RSA, name="RSA"),
    path('Diffie-hellman/', views.Diffie_hellman, name="Diffie-hellman"),
    path('Shamir/', views.Shamir, name="Shamir"),
    path('Elgamal/', views.Elgamal, name="Elgamal"),
    path('MD5/', views.MD5, name="MD5"),
    path('SHA/', views.SHA, name="SHA"),
    path('hashRSA/', views.hashRSA, name="hashRSA"),
    path('hashELGamal/', views.hashELGamal, name="hashELGamal"),
]
