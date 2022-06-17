import os.path as path
from flask import request
import jwt
from datetime import datetime

rootDir = path.abspath(path.join(__file__, "./../../certs"))
JWT_PRIVATE_KEY = open(path.join(rootDir, "private.key")).read()
JWT_PUBLIC_KEY = open(path.join(rootDir, "public.pem")).read()


# helper functions for generating responses
def generateResponse(message):
    return {
        "status": "200",
        "data": message
    }


def generateError(code, message):
    return (
        {
            "status": code,
            "error": message
        },
        code
    )


# helper functions for jwt tokens
def validateJWTTimeValidity(payload):
    issuedTime = datetime.strptime(
        str(payload['issued']), '%Y-%m-%d %H:%M:%S.%f')
    # check issued time is in the past
    if not (issuedTime < datetime.now()):
        return False

    expiryTime = datetime.strptime(
        str(payload['expires']), '%Y-%m-%d %H:%M:%S.%f')
    # check expiry time is in the future
    if not (expiryTime > datetime.now()):
        return False

    return True


# function to decode jwt_token
def validateJWT(request):
    try:
        token = request.cookies.get('jwt_token')
        payload = jwt.decode(token, JWT_PUBLIC_KEY, algorithms=['RS512'])

        if not validateJWTTimeValidity(payload):
            return False

        return payload
    except:
        return False


# function to decode jwt_permissions
def getJWTPermissions(request, id_token):
    try:
        permission_token = request.cookies.get('jwt_permissions')
        permission_payload = jwt.decode(permission_token, JWT_PUBLIC_KEY, algorithms=['RS512'])  # nopep8

        if not validateJWTTimeValidity(permission_payload):
            return False

        if id_token['userID'] != permission_payload['userID']:
            return False

        return permission_payload
    except:
        return False


# function to retrieve id and permission tokens from request
def getDecodedJWTTokens(request):
    # get and validate jwt id token
    try:
        id_token = validateJWT(request)
    except:
        raise Exception(500, "Could not validate jwt_token")  # nopep8
    if (not id_token):
        raise Exception(400, "Invalid jwt_token")

    # get and validate jwt permissions token
    else:
        try:
            perm_token = getJWTPermissions(request, id_token)
        except:
            raise Exception(500, "Could not validate jwt_permissions")  # nopep8
        if (not perm_token):
            raise Exception(400, "Invalid jwt_permissions")

    return id_token, perm_token


# helper function to paginate array
def paginateArray(array, pageSize):
    for i in range(0, len(array), pageSize):
        yield array[i:i + pageSize]


# helper function to remove duplicates
def addWithoutDuplicating(arr1, arr2):
    # check if item is present in arr1, and if not add it
    for itemToAdd in arr2:
        shouldAdd = True
        for itemToCheck in arr1:
            if itemToAdd['id'] == itemToCheck['id']:
                shouldAdd = False
        if (shouldAdd):
            arr1.append(itemToAdd)
    return arr1


# helper function to check if user is admin
def isUserAdmin(perm_token):
    for role in perm_token['roles']:
        if role['name'] == 'admin':
            return True
    return False
