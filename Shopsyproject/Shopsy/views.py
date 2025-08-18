from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.template import loader
import json
import re
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User
from .models import Product
from .models import Order
from django.contrib.auth.hashers import check_password
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from functools import wraps
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import base64
from decimal import Decimal

# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .serializers import SignupSerializer


def check_admin(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user_id = request.session.get('user_id')
        try:
            user = User.objects.get(id=user_id)
            if not user.is_admin:
                return JsonResponse({"message": "Access denied. Admin privileges required."}, status=403)
        except User.DoesNotExist:
            return JsonResponse({"message": "Please login first"}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def Homepage(request):
    template = loader.get_template('index.html')
    user_id = request.session.get('user_id')
    context = {}
    
    if user_id:
        try:
            user = User.objects.get(id=user_id)
            context = {
                'user': {
                    'name': user.name,
                    'is_admin': user.is_admin
                }
            }
        except User.DoesNotExist:
            pass
            
    return HttpResponse(template.render(context, request))

# class SignupView(APIView):
#     def post(self, request):
#         serializer = SignupSerializer(data=request.data)
        
#         if serializer.is_valid():
#             return Response({
#                 "message": "register successfully",
#                 "is_register": True
#             }, status=status.HTTP_200_OK)
        
#         return Response({
#             "message": "register failed",
#             "is_register": False,
#             "region": serializer.errors
#         }, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt  # Disable CSRF for simplicity (not recommended for production)
def signup_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        email = data.get("email")
        mobile = data.get("mobile")
        name = data.get("name")
        password = data.get("password")
        role = data.get("role", "user")  # Default to 'user' if not specified

        # Validate role
        if role not in ['user', 'admin']:
            role = 'user'  # Default to user if invalid role

        errors = {}

        if not email or "@" not in email:
            errors["email"] = "Invalid email format"

        if not mobile or not mobile.isdigit() or len(mobile) < 10:
            errors["mobile"] = "Invalid mobile number"

        if not name or len(name) < 3:
            errors["name"] = "Name must be at least 3 characters long"

        if not password or not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$', password):
            errors["password"] = "Password must contain letters and numbers, min length 6"

        if errors:
            return JsonResponse({"message": "Register failed", "is_register": False, "errors": errors}, status=400)
        
        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return JsonResponse({"message": "Email already exists", "is_register": False}, status=400)

        if User.objects.filter(mobile=mobile).exists():
            return JsonResponse({"message": "Mobile number already registered", "is_register": False}, status=400)

        # Create new user with hashed password
        user = User(name=name, email=email, mobile=mobile, role=role)
        user.set_password(password)
        user.save()
        
        # Set session data
        request.session['user_id'] = user.id
        request.session['user_name'] = user.name
        request.session['is_admin'] = user.is_admin
        
        return JsonResponse({
            "message": "Register successfully", 
            "is_register": True,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "is_admin": user.is_admin
            }
        }, status=200)

    return JsonResponse({"message": "Invalid request method"}, status=405)

    
@csrf_exempt
def login_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        email = data.get('email')
        password = data.get('password')

        errors = {}

        if not email or email.strip() == "":
            errors["email"] = "Email cannot be blank"

        if not password or len(password) < 6:
            errors["password"] = "Invalid password details"

        if errors:
            return JsonResponse({"message": "Invalid input", "errors": errors}, status=400)

        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                # Update last login time
                user.update_last_login()
                
                # Set session data
                request.session['user_id'] = user.id
                request.session['user_name'] = user.name
                request.session['is_admin'] = user.is_admin
                
                return JsonResponse({
                    "message": "Login successful",
                    "login": True,
                    "user": {
                        "id": user.id,
                        "name": user.name,
                        "email": user.email,
                        "role": user.role,
                        "is_admin": user.is_admin,
                        "redirect_url": '/dashboard/products/' if user.is_admin else '/'
                    }
                }, status=200)
            else:
                return JsonResponse({"message": "Invalid email or password", "login": False}, status=401)
        except User.DoesNotExist:
            return JsonResponse({"message": "Invalid email or password", "login": False}, status=401)

    return JsonResponse({"message": "Invalid request"}, status=405)

@csrf_exempt
def logout_view(request):
    if request.method == "POST":
        # Clear session data
        request.session.flush()
        return JsonResponse({"message": "Logged out successfully"}, status=200)
    return JsonResponse({"message": "Invalid request method"}, status=405)

@csrf_exempt
def check_auth(request):
    """Check if user is authenticated"""
    user_id = request.session.get('user_id')
    if user_id:
        try:
            user = User.objects.get(id=user_id)
            return JsonResponse({
                "is_authenticated": True,
                "user": {
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                    "is_admin": user.is_admin
                }
            })
        except User.DoesNotExist:
            pass
    
    return JsonResponse({
        "is_authenticated": False
    })

@check_admin
def admin_products(request):
    """Admin products management page"""
    user_id = request.session.get('user_id')
    try:
        user = User.objects.get(id=user_id)
        return render(request, 'admin_products.html', {'user': user})
    except User.DoesNotExist:
        return redirect('/')

@csrf_exempt
def get_product_detail(request, product_id):
    """Get details of a specific product"""
    try:
        product = Product.objects.get(id=product_id)
        return JsonResponse({
            "id": product.id,
            "productname": product.productname,
            "productprice": str(product.productprice),
            "description": product.description,
            "discount": product.discount,
            "image": product.image.url if product.image else None,
            "create_by": product.create_by,
            "create_date": product.create_date.strftime("%Y-%m-%d")
        })
    except Product.DoesNotExist:
        return JsonResponse({"message": "Product not found"}, status=404)

@csrf_exempt
@check_admin
def product_view(request):
    if request.method == "POST":
        try:
            productname = request.POST.get("productname")
            productprice = request.POST.get("productprice")
            description = request.POST.get("description")
            discount = request.POST.get("discount", 0)
            image = request.FILES.get("image")

            error = {}

            if not productname or productname.strip() == "":
                error["productname"] = "Product name cannot be blank"

            if error:
                return JsonResponse({"is_product_create": False, "message": "Product not created", "errors": error}, status=400)

            user = User.objects.get(id=request.session.get('user_id'))
            product = Product(
                productname=productname,
                productprice=productprice,
                description=description,
                discount=discount,
                create_by=user.name
            )

            if image:
                product.image = image

            product.save()

            return JsonResponse({
                "is_product_create": True,
                "message": "Product created successfully",
                "product": {
                    "id": product.id,
                    "productname": product.productname,
                    "productprice": str(product.productprice),
                    "description": product.description,
                    "discount": product.discount,
                    "image": product.image.url if product.image else None
                }
            }, status=200)
        except Exception as e:
            return JsonResponse({"is_product_create": False, "message": str(e)}, status=500)

    return JsonResponse({"message": "Method Not Allowed"}, status=405)

    
@csrf_exempt
def get_product_view(request):
    """Retrieves all product details"""
    if request.method == "GET":
        products = Product.objects.all()
        product_list = []
        for product in products:
            product_data = {
                "id": product.id,
                "productname": product.productname,
                "productprice": str(product.productprice),
                "description": product.description,
                "discount": product.discount,
                "create_by": product.create_by,
                "create_date": product.create_date.strftime("%Y-%m-%d"),
                "image": request.build_absolute_uri(product.image.url) if product.image else None,
                "final_price": str(product.final_price)
            }
            product_list.append(product_data)
        return JsonResponse({"products": product_list}, status=200)

    return JsonResponse({"message": "Method Not Allowed"}, status=405) 


@csrf_exempt
@check_admin
def delete_product_view(request, product_id):
    """Deletes a product by its ID"""
    if request.method == "DELETE":
        try:
            product = Product.objects.get(id=product_id)
            product.delete()
            return JsonResponse({"is_deleted": True, "message": "Product deleted successfully"}, status=200)
        except Product.DoesNotExist:
            return JsonResponse({"is_deleted": False, "message": "Product not found"}, status=404)

    return JsonResponse({"message": "Method Not Allowed"}, status=405)



@csrf_exempt
@check_admin
def update_product_view(request, product_id):
    """Updates a product by its ID"""
    if request.method in ["PUT", "POST"]:  # Accept both PUT and POST for form data
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return JsonResponse({"is_updated": False, "message": "Product not found"}, status=404)

        try:
            # Get updated fields from request
            data = request.POST if request.POST else json.loads(request.body)
            
            # Update fields if provided
            if 'productname' in data:
                product.productname = data['productname']
            if 'productprice' in data:
                try:
                    product.productprice = Decimal(str(data['productprice']))
                except (TypeError, ValueError):
                    return JsonResponse({
                        "is_updated": False,
                        "message": "Invalid price format"
                    }, status=400)
            if 'description' in data:
                product.description = data['description']
            if 'discount' in data:
                try:
                    product.discount = int(float(data['discount']))
                except (TypeError, ValueError):
                    return JsonResponse({
                        "is_updated": False,
                        "message": "Invalid discount format"
                    }, status=400)

            # Handle image update if provided
            if request.FILES and 'image' in request.FILES:
                product.image = request.FILES['image']
            
            # Update create_by to current admin's name
            try:
                user = User.objects.get(id=request.session.get('user_id'))
                product.create_by = user.name
            except User.DoesNotExist:
                pass

            product.save()

            return JsonResponse({
                "is_updated": True,
                "message": "Product updated successfully",
                "product": {
                    "id": product.id,
                    "productname": product.productname,
                    "productprice": str(product.productprice),
                    "description": product.description,
                    "discount": product.discount,
                    "image": request.build_absolute_uri(product.image.url) if product.image else None,
                    "create_by": product.create_by,
                    "create_date": product.create_date.strftime("%Y-%m-%d"),
                    "final_price": str(product.final_price)
                }
            }, status=200)
        except Exception as e:
            return JsonResponse({
                "is_updated": False,
                "message": f"Error updating product: {str(e)}"
            }, status=500)

    return JsonResponse({"message": "Method Not Allowed"}, status=405)


@csrf_exempt
def create_order(request):
    """Creates an order"""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        product_id = data.get("product_id")
        quantity = data.get("quantity", 1)

        try:
            # Get the product
            product = Product.objects.get(id=product_id)

            # Create initial order with minimal details
            order = Order(
                user=None,  # No user required
                product=product,
                quantity=quantity,
                price=product.final_price,  # Use the discounted price if available
                delivery_charge=50.00,  # Default delivery charge
                # Set temporary values for required fields
                full_name="Guest Order",
                phone="Not provided",
                house_no="Not provided",
                city="Not provided",
                state="Not provided",
                pincode="Not provided"
            )
            order.save()

            return JsonResponse({
                "success": True,
                "message": "Order initiated successfully",
                "order": {
                    "id": order.id,
                    "product_name": product.productname,
                    "quantity": quantity,
                    "price": str(product.final_price),
                    "total": str(order.total_price)
                }
            }, status=201)

        except Product.DoesNotExist:
            return JsonResponse({"message": "Product not found"}, status=404)
        except Exception as e:
            return JsonResponse({"message": f"Error creating order: {str(e)}"}, status=500)

    return JsonResponse({"message": "Method Not Allowed"}, status=405)


# @csrf_exempt
def get_order_details(request, order_id):
    """Retrieve details of a specific order"""
    if request.method == "GET":
        try:
            order = Order.objects.get(id=order_id)
            response_data = {
                "order_id": order.id,
                "user": order.user.username,
                "product": order.product.productname,
                "quantity": order.quantity,
                "price": str(order.price),
                "delivery_charge": str(order.delivery_charge),
                "total_price": str(order.total_price),
                "status": order.status,
                "order_date": order.order_date.strftime("%Y-%m-%d %H:%M:%S"),
                "full_name": order.full_name,
                "phone": order.phone,
                "house_no": order.house_no,
                "landmark": order.landmark,
                "city": order.city,
                "state": order.state,
                "pincode": order.pincode,
            }
            return JsonResponse(response_data, status=200)

        except Order.DoesNotExist:
            return JsonResponse({"message": "Order not found"}, status=404)

    return JsonResponse({"message": "Method Not Allowed"}, status=405)
