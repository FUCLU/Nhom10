"""Functional and policy enforcement tests for json_search."""

import unittest

try:
    from .recursive_json_search import json_search
    from .policy import POLICY
    from .test_data import data, key1
except ImportError:
    from recursive_json_search import json_search
    from policy import POLICY
    from test_data import data, key1


class json_search_test(unittest.TestCase):
    def test_search_found(self):
        """Find an authorized key present in nested input."""
        self.assertEqual(
            [{key1: "Network Device 10.10.20.82 Is Unreachable From Controller"}],
            json_search(key1, data, role="admin"),
        )

    def test_search_not_found(self):
        """Return an empty list when an authorized key is absent."""
        self.assertEqual([], json_search(key1, {"unrelated": "value"}, role="admin"))

    def test_is_a_list(self):
        """Return matches as a list and aggregate matches inside lists."""
        result = json_search(key1, {"items": [{key1: "first"}, {key1: "second"}]}, role="admin")
        self.assertIsInstance(result, list)
        self.assertEqual([{key1: "first"}, {key1: "second"}], result)

    def test_policy_authorized_roles_can_read_each_field(self):
        """SR-1: every role listed for each policy field can receive its value."""
        for field, allowed_roles in POLICY.items():
            with self.subTest(field=field):
                sample = {field: "sentinel"}
                for role in allowed_roles:
                    with self.subTest(role=role):
                        self.assertEqual([{field: "sentinel"}], json_search(field, sample, role=role))

    def test_policy_unauthorized_roles_cannot_read_each_field(self):
        """SR-1: roles absent from each field's policy receive no value."""
        roles = {"admin", "operator", "viewer", "unknown"}
        for field, allowed_roles in POLICY.items():
            unauthorized_roles = roles.difference(allowed_roles)
            with self.subTest(field=field):
                sample = {field: "sentinel"}
                for role in unauthorized_roles:
                    with self.subTest(role=role):
                        self.assertEqual([], json_search(field, sample, role=role))

    def test_unknown_key_and_missing_role_are_denied(self):
        """Unknown fields and omitted roles are denied by default."""
        self.assertEqual([], json_search("unknownField", {"unknownField": "secret"}, role="admin"))
        self.assertEqual([], json_search("apiKey", {"apiKey": "secret"}))


if __name__ == "__main__":
    unittest.main()
