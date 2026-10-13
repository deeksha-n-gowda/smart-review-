"""
Rate throttling for the Smart Review API.

- UserRateThrottle: 100 requests/minute per authenticated user
- AnonymousRateThrottle: 50 requests/minute for unauthenticated clients
"""

from rest_framework.throttling import UserRateThrottle, AnonymousRateThrottle


class UserRateThrottle(UserRateThrottle):
    """Per-user rate limit: 100 requests/minute."""
    scope = "user"


class AnonymousRateThrottle(AnonymousRateThrottle):
    """Rate limit for unauthenticated clients: 50 requests/minute."""
    scope = "anonymous"