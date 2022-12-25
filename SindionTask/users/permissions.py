from rest_framework import permissions


class OwnProfilePermission(permissions.BasePermission):
    """
    Object-level permission to only allow updating his own profile
    """

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user

class IsEmployeeUser(permissions.BasePermission):
    
    def has_permission(self, request, view):
        if request.user.user_type == 'employee':
            return True
        
        return False