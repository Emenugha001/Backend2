# permissions.py
from rest_framework import permissions


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or admins to access it.
    """

    def has_object_permission(self, request, view, obj):
        # Admin users have full access
        if request.user.role == 'admin':
            return True
        
        # Users can only access their own files
        return obj.owner == request.user


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users.
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'admin'


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    Read permissions are allowed to any authenticated user.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any authenticated request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the object or admin.
        return obj.owner == request.user or request.user.role == 'admin'