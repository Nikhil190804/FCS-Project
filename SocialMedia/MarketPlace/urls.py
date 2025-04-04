from django.urls import path
from . import views
from .views import delete_from_cart

app_name = 'MarketPlace'

urlpatterns = [
    path('listings/', views.listings, name='listings'),
    path('listings/new/', views.create_listing, name='create_listing'),
    path('listings/<int:id>/buy/', views.purchase, name='purchase'),
    path('orders/', views.my_orders, name='my_orders'),
]

urlpatterns += [
    path('cart/', views.view_cart, name='view_cart'),
    path('cart/add/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('listings/<int:product_id>/delete/', views.delete_product, name='delete_product'), 
    path('order/', views.order, name='order'),
    path('order-confirmation/', views.order_confirmation, name='order_confirmation'),
    path('cart/delete/<int:item_id>/', delete_from_cart, name='delete_from_cart'),


]

