"""RLScout — an authorized-testing detector for missing/broken Supabase RLS.

This is a *detector, not an exploiter*. It performs read-only, in-scope checks
to determine whether an unauthenticated client can read tables it shouldn't, and
points a human at the result. It never writes, never leaves scope, and never
captures record contents. See CLAUDE.md for the full working agreement.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
