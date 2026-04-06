from django.urls import path
from .views import ThreatLogView, AttackStatsView, AttackTypeView, TopIPView,BlockIPView, ResolveIncidentView, IgnoreIncidentView


urlpatterns = [
    path('logs/', ThreatLogView.as_view()),
    path('stats/', AttackStatsView.as_view()),
    path('types/', AttackTypeView.as_view()),
    path('top-ips/', TopIPView.as_view()),
    path('actions/block-ip/', BlockIPView.as_view()),
    path('actions/resolve-incident/', ResolveIncidentView.as_view()),
    path('actions/ignore-incident/', IgnoreIncidentView.as_view()),
]