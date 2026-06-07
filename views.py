from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Profile
from .forms import ProfileForm


@login_required
def dashboard(request):
    profile, created = Profile.objects.get_or_create(user=request.user)

    return render(request, "accounts/dashboard.html", {
        "profile": profile
    })


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

    return render(request, "accounts/edit_profile.html", {
        "form": form
    })
