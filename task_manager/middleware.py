import jwt
from django.conf import settings
from channels.db import database_sync_to_async
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import UntypedToken
from accounts.models import User  # Assuming your custom User model

@database_sync_to_async
def get_user_from_token(token):
    try:
        # Validate the token
        UntypedToken(token)
        decoded = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms=[settings.SIMPLE_JWT['ALGORITHM']])
        user_id = decoded.get('user_id')
        return User.objects.get(id=user_id)
    except (InvalidToken, TokenError, User.DoesNotExist, jwt.PyJWTError):
        return None

class JwtAuthMiddleware:
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        # Extract token from headers (e.g., Authorization: Bearer <token>)
        headers = dict(scope['headers'])
        auth_header = headers.get(b'authorization', b'').decode('utf-8')
        token = None
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        # If no token in headers, fallback to query string (optional, for flexibility)
        if not token:
            query_string = scope['query_string'].decode()
            for param in query_string.split('&'):
                if param.startswith('token='):
                    token = param.split('=')[1]
                    break

        if token:
            user = await get_user_from_token(token)
            if user:
                scope['user'] = user

        # Proceed to the next middleware or consumer
        return await self.inner(scope, receive, send)
