"""dns_tools URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include, url
from django.contrib import admin
from . import views

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^domain_information/',views.get_domain_information),
    url(r'^get_ip_attribution/',views.get_ip_attribution),
    url(r'^get_localdns_result/',views.get_localdns_result),
    url(r'^get_authority_result/',views.get_authority_result),
    url(r'^get_dns_cache/',views.get_dns_cache),
    url(r'^get_device_load/',views.get_device_load),
    url(r'^get_ip_attribution_url/',views.get_ip_attribution_url),
    url(r'^customize/',views.customize),
    #url(r'^get_ecs_resolve/',views.get_ecs_resolve)
    url(r'^get_name/',views.get_name)
]