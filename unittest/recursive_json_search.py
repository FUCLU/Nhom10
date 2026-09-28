"""Role-aware recursive search for values in JSON-like Python objects."""

try:  # Support both module execution from this directory and package imports.
    from .policy import POLICY
except ImportError:
    from policy import POLICY


def json_search(key, input_object, role=None):
    """Return all ``{key: value}`` matches that the caller's role may read.

    Results are collected throughout nested dictionaries and lists. Access is
    denied by default for missing roles and keys absent from ``POLICY``.
    """
    allowed_roles = POLICY.get(key, ())
    if role not in allowed_roles:
        return []

    results = []

    def visit(value):
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                if child_key == key:
                    results.append({child_key: child_value})
                visit(child_value)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(input_object)
    return results
