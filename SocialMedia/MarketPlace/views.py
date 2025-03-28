# from django.shortcuts import render

# def listings(request):
#     return render(request, 'MarketPlace/listings.html')

# def create_listing(request):
#     return render(request, 'MarketPlace/create_listing.html')

from django.shortcuts import render, redirect
from .models import Product
from .forms import ProductForm
from django.shortcuts import get_object_or_404
from .models import CartItem, Product, Order, OrderItem
from django.views import generic
from Users.models import User

def listings(request):
    products = Product.objects.all()
    return render(request, 'MarketPlace/listings.html', {'products': products})

def create_listing(request):
    if request.method == "POST":
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('MarketPlace:listings')
    else:
        form = ProductForm()
    
    return render(request, 'MarketPlace/create_listing.html', {'form': form})

def purchase(request, id):
    return render(request, 'MarketPlace/purchase.html', {'id': id})

def my_orders(request):
    return render(request, 'MarketPlace/my_orders.html')

def add_to_cart(request, product_id):
    user = get_current_user(request)
    if not user:
        return redirect("Users:login")  # Redirect to login if not authenticated

    product = get_object_or_404(Product, id=product_id)
    quantity = int(request.POST.get("quantity", 1))

    cart_item, created = CartItem.objects.get_or_create(user=user, product=product)
    if not created:
        cart_item.quantity += quantity
    cart_item.save()

    return redirect("MarketPlace:view_cart")

def view_cart(request):
    current_user_id = request.session.get("current_user")
    cart_items = CartItem.objects.filter(user_id=current_user_id)

    for item in cart_items:
        item.subtotal = item.product.price * item.quantity  # Calculate subtotal

    total_price = sum(item.subtotal for item in cart_items)

    return render(request, 'MarketPlace/cart.html', {
        'cart_items': cart_items,
        'total_price': total_price
    })

def delete_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    if request.method == "POST":
        # Delete all cart items related to this product
        CartItem.objects.filter(product=product).delete()

        # Delete the product itself
        product.delete()

    return redirect('MarketPlace:listings')

def order(request):
    user = get_current_user(request)
    if not user:
        return redirect("Users:login")

    cart_items = CartItem.objects.filter(user=user)
    if cart_items.exists():
        total_price = sum(item.product.price * item.quantity for item in cart_items)
        order = Order.objects.create(user=user, total_price=total_price)

        for item in cart_items:
            OrderItem.objects.create(order=order, product=item.product, quantity=item.quantity, price_at_purchase=item.product.price)

        cart_items.delete()  # Clear cart after order placement

        return redirect("MarketPlace:order_confirmation")

    return redirect("MarketPlace:view_cart")

def my_orders(request):
    user = get_current_user(request)
    if not user:
        return redirect("Users:login")

    orders = Order.objects.filter(user=user).prefetch_related("order_items")

    return render(request, "MarketPlace/my_orders.html", {"orders": orders})

def order_confirmation(request):
    return render(request, 'MarketPlace/order_confirmation.html')

def get_current_user(request):
    """Retrieve the currently logged-in user from the session."""
    current_user_id = request.session.get("current_user")
    if not current_user_id:
        return None  # No user in session
    return User.objects.filter(user_id=current_user_id).first()
#for payments

# import stripe
# from django.conf import settings
# # This is your test secret API key.
# stripe.api_key = settings.STRIPE_SECRET_KEY

# class CreateCheckoutSessionView(generic.View):
#     def post(self, request, *args, **kwargs):
#         YOUR_DOMAIN = "http://127.0.0.1:8000"  # Change to your actual domain in production

#         checkout_session = stripe.checkout.Session.create(
#             payment_method_types=['card'],
#             line_items=[
#                 {
#                     'price_data': {
#                         'currency': 'inr',  # Set currency
#                         'product_data': {
#                             'name': 'Cart Purchase',  # General name for cart purchase
#                         },
#                         'unit_amount': int(request.POST.get('amount', 0)) * 100,  # Convert to paisa
#                     },
#                     'quantity': 1,
#                 },
#             ],
#             mode='payment',
#             success_url=YOUR_DOMAIN + '/order-confirmation/',  # Redirect to order confirmation
#             cancel_url=YOUR_DOMAIN + '/cart/',  # Redirect back to cart if canceled
#         )

#         return redirect(checkout_session.url, code=303)

