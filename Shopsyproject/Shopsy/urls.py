from django.urls import path
from . import views
# from .views import SignupView

urlpatterns = [
    path("", views.Homepage, name="homepage"),
    path("signup/", views.signup_view, name="signup"),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('check-auth/', views.check_auth, name='check-auth'),
    path('dashboard/products/', views.admin_products, name='admin_products'),
    path('createProduct/', views.product_view, name='create_product'),
    path('getProduct/', views.get_product_view, name='get_product'),
    path('getProduct/<int:product_id>/', views.get_product_detail, name='get_product_detail'),
    path('deleteProduct/<int:product_id>/', views.delete_product_view, name='delete_product'),
    path('updateProduct/<int:product_id>/', views.update_product_view, name='update_product'),
    path('create-order/', views.create_order, name='create-order'),
]