from ninja import NinjaAPI
api = NinjaAPI(title="Himalay Suraksha API", version="1.0.0")
@api.get("/hello")
def hello(request):
    return {"message": "Hello, world!"}