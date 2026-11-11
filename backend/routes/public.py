"""
Public-facing dummy endpoints for testing.
These simulate a real web application that can be hit by the test script.
"""
from fastapi import APIRouter

router = APIRouter(prefix="/api/public", tags=["public"])


@router.get("/home")
async def home():
    return {"page": "home", "message": "Welcome to the application"}


@router.get("/about")
async def about():
    return {"page": "about", "message": "About our security monitoring platform"}


@router.get("/products")
async def products():
    return {"page": "products", "products": ["Product A", "Product B", "Product C"]}


@router.get("/contact")
async def contact():
    return {"page": "contact", "email": "contact@example.com"}


@router.get("/services")
async def services():
    return {"page": "services", "services": ["Consulting", "Development", "Support"]}


@router.get("/blog")
async def blog():
    return {"page": "blog", "posts": [{"title": "Security Best Practices", "id": 1}]}


@router.get("/faq")
async def faq():
    return {"page": "faq", "questions": ["What is this?", "How does it work?"]}


@router.get("/pricing")
async def pricing():
    return {"page": "pricing", "plans": ["Free", "Pro", "Enterprise"]}


@router.get("/status")
async def status():
    return {"status": "healthy", "uptime": "99.9%"}
