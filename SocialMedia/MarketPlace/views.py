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
from django.db import transaction
from django.http import HttpResponseRedirect
from django.urls import reverse

def delete_from_cart(request, item_id):
    """Delete a specific item from the cart."""
    cart_item = get_object_or_404(CartItem, id=item_id)

    # Check if the logged-in user owns the cart item
    if request.session.get("current_user") != cart_item.user_id:
        return redirect("MarketPlace:view_cart")  # Redirect if unauthorized

    cart_item.delete()
    return HttpResponseRedirect(reverse("MarketPlace:view_cart"))

def listings(request):
    user = get_current_user(request)  # Fetch the logged-in user
    if not user:
        return redirect("Users:login")  # Redirect if not authenticated

    query = request.GET.get('q', '')
    if query:
        if len(query) > 100:
            CONTEXT = {
                        "heading":"Error",
                        "message":"Search Query Length Too Big !",
                        "button_url":"MarketPlace:listings"
                    }
            return render(request,"Socialmedia/error.html",CONTEXT)
        products = Product.objects.filter(name__istartswith=query)  # Only products that START with query
    else:
        products = Product.objects.all()
    
    return render(request, 'MarketPlace/listings.html', {
        'products': products,
        'user': user  # Pass user to the template
    })

def create_listing(request):
    user = get_current_user(request)  # Fetch the current user
    if not user:
        return redirect("Users:login")  # Redirect to login if not authenticated

    if request.method == "POST":
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            product = form.save(commit=False)
            product.seller = user  # Assign the logged-in user as the seller
            product.save()
            return redirect('MarketPlace:listings')
        else:
            CONTEXT = {
                        "heading":"Error",
                        "message":"Wrong Fields In Listing Creation!",
                        "button_url":"MarketPlace:listings"
                    }
            return render(request,"Socialmedia/error.html",CONTEXT)

    else:
        form = ProductForm()

    return render(request, 'MarketPlace/create_listing.html', {'form': form})



def add_to_cart(request, product_id):
    user = get_current_user(request)
    if not user:
        return redirect("Users:login") 

    product = get_object_or_404(Product, id=product_id)
    
    try:
        quantity = int(request.POST.get("quantity", 1))
        cart_item, created = CartItem.objects.get_or_create(user=user, product=product)
        if created:
            cart_item.quantity = quantity  
        else:
            cart_item.quantity += quantity
        cart_item.save()
        return redirect("MarketPlace:view_cart")
    except Exception as e:
        CONTEXT = {
                        "heading":"Error",
                        "message":"Invalid Qunatity In Cart!",
                        "button_url":"MarketPlace:listings"
                    }
        return render(request,"Socialmedia/error.html",CONTEXT)


    

    

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



def order(request):
    user = get_current_user(request)
    if not user:
        return redirect("Users:login")

    cart_items = CartItem.objects.filter(user=user)
    if not cart_items.exists():
        return redirect("MarketPlace:view_cart")

    total_price = sum(item.product.price * item.quantity for item in cart_items)

    # Check if the user has enough balance
    if user.wallet_balance < total_price:
        CONTEXT = {
                        "heading":"Error",
                        "message":"Not Enough Balance!",
                        "button_url":"MarketPlace:listings"
                    }
        return render(request,"Socialmedia/error.html",CONTEXT)

    # Process Order within a transaction to ensure consistency
    try:
        with transaction.atomic():
            order = Order.objects.create(user=user, total_price=total_price)

            for item in cart_items:
                # Create order items

                product = item.product
                seller = product.seller
                OrderItem.objects.create(order=order, product=item.product, quantity=item.quantity, price_at_purchase=item.product.price)

                # Deduct money from the buyer's wallet
                if(seller == user):
                    raise ValueError("You Are Already The Seller Of This Product !!")
                else:
                    amount = product.price * item.quantity
                    user.wallet_balance -= amount
                    seller.wallet_balance += amount
                    seller.save() 
                    user.save()  

            cart_items.delete()
            return redirect("MarketPlace:order_confirmation")

    except ValueError as ve:
        CONTEXT = {
                        "heading":"Error",
                        "message":"You are Already The Seller Of The Product !",
                        "button_url":"MarketPlace:listings"
                    }
        return render(request,"Socialmedia/error.html",CONTEXT)
    
    except Exception as e:
        CONTEXT = {
                        "heading":"Error",
                        "message":"Backend Error !",
                        "button_url":"MarketPlace:listings"
                    }
        return render(request,"Socialmedia/error.html",CONTEXT)


    


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
        return None 
    return User.objects.filter(user_id=current_user_id).first()
