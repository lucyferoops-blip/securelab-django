from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User

from .models import Profile
from .forms import ProfileForm


def home(request):
    return render(request, "accounts/home.html")


def user_login(request):
    error = None

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect('dashboard')
        else:
            error = "Invalid username or password"

    return render(request, 'accounts/login.html', {"error": error})


def register(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username and password:
            if not User.objects.filter(username=username).exists():
                User.objects.create_user(username=username, password=password)
                return redirect('login')

    return render(request, 'accounts/register.html')


@login_required
def dashboard(request):
    profile, created = Profile.objects.get_or_create(user=request.user)

    return render(request, "accounts/dashboard.html", {
        "profile": profile
    })


def user_logout(request):
    logout(request)
    return redirect('login')


@login_required
def edit_profile(request):
    profile, created = Profile.objects.get_or_create(user=request.user)

    if request.method == "POST":
        form = ProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = ProfileForm(instance=profile)

    return render(request, 'accounts/edit_profile.html', {
        'form': form
    })
