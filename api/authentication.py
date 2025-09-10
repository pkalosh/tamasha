from rest_framework import exceptions
import datetime,   jwt
from rest_framework.authentication import BasicAuthentication, get_authorization_header
from .models import User


class JWTAuthentication(BasicAuthentication):
    def authenticate(self, request):

        auth = get_authorization_header(request).split()
        print('JWT AUTH')
        print(auth)
        if auth and len(auth) == 2:
            token = auth[1].decode("utf-8")
            id = decode_access_token(token)
            user = User.objects.get(pk=id)
            return (user, None)
            

        raise exceptions.PermissionDenied("unauthenticated")
        return super().authenticate(request)


def create_access_token(id):
    user_id: id
    return jwt.encode(
        {
            "user_id": id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            "iat": datetime.datetime.utcnow(),
        },
        "access_secret",
        algorithm="HS256",
    )


def decode_access_token(token):
    try:
        payload = jwt.decode(token, "access_secret", algorithms=["HS256"])
        return payload["user_id"]
    except Exception as e:
        print(e)
        raise exceptions.PermissionDenied("unauthorized")


def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, "refresh_secret", algorithms=["HS256"])
        return payload["user_id"]
    except Exception as e:
        print(e)
        raise exceptions.AuthenticationFailed("unauthenticated")


def create_refresh_token(id):
    user_id: id
    return jwt.encode(
        {
            "user_id": id,
            # days=7
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=2),
            "iat": datetime.datetime.utcnow(),
        },
        "refresh_secret",
        algorithm="HS256",
    )
