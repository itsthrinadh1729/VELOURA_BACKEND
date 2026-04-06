from django.db import models
from django.conf import settings

User = settings.AUTH_USER_MODEL

class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"Cart of {self.user}"


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name="items")
    product_id = models.IntegerField()   # from frontend
    name = models.CharField(max_length=255)
    price = models.FloatField()
    quantity = models.IntegerField(default=1)

    def __str__(self):
        return self.name