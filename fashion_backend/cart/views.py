from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Cart, CartItem
from .serializers import CartItemSerializer

class AddToCartView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        cart, _ = Cart.objects.get_or_create(user=user)

        product_id = request.data.get("product_id")
        name = request.data.get("name")
        price = request.data.get("price")

        item, created = CartItem.objects.get_or_create(
            cart=cart,
            product_id=product_id,
            defaults={"name": name, "price": price}
        )

        if not created:
            item.quantity += 1
            item.save()

        return Response({"message": "Item added"})


class ViewCartView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cart, _ = Cart.objects.get_or_create(user=request.user)
        items = cart.items.all()

        serializer = CartItemSerializer(items, many=True)
        return Response(serializer.data)


class RemoveFromCartView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        product_id = request.data.get("product_id")

        cart = Cart.objects.get(user=request.user)
        CartItem.objects.filter(cart=cart, product_id=product_id).delete()

        return Response({"message": "Item removed"})