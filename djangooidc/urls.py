# coding: utf-8

from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^login$', views.openid, name='openid'),
    url(r'^openid/(?P<op_name>.+)$', views.openid, name='openid_with_op_name'),
    url(r'^callback/login/?$', views.authz_cb, name='openid_login_cb'),
    url(r'^logout$', views.logout, name='logout'),
    url(r'^callback/logout/?$', views.logout_cb, name='openid_logout_cb'),
]