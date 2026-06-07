from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # 👈 این مهمه
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.user_logout, name='logout'),
    path('edit-profile/', views.edit_profile, name='edit_profile'),
]
