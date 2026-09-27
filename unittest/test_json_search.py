# Fill the Python code in this file
import unittest
from recursive_json_search import *
from test_data import *

class json_search_test(unittest.TestCase):
    '''test module to test search function in
`recursive_json_search.py`'''
    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([]!=json_search(key1,data,role="admin"))
    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([]==json_search(key2,data,role="admin"))
    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1,data,role="admin"),list)


class json_search_security_test(unittest.TestCase):
    '''test module to validate role-based access control per policy.py — verifies SR-1 (T4, T6)'''

    def test_wrong_role_cannot_read_apikey(self):
        '''SR-1: viewer must not receive apiKey (admin-only)'''
        self.assertEqual([], json_search("apiKey", data, role="viewer"))

    def test_operator_cannot_read_apikey(self):
        '''SR-1: operator must not receive apiKey (admin-only)'''
        self.assertEqual([], json_search("apiKey", data, role="operator"))

    def test_admin_can_read_apikey(self):
        '''SR-1: admin is allowed to receive apiKey'''
        self.assertNotEqual([], json_search("apiKey", data, role="admin"))

    def test_viewer_cannot_read_management_ip(self):
        '''SR-1: viewer must not receive managementIpAddress (admin+operator only)'''
        self.assertEqual([], json_search("managementIpAddress", data, role="viewer"))

    def test_operator_can_read_management_ip(self):
        '''SR-1: operator is allowed to receive managementIpAddress'''
        self.assertNotEqual([], json_search("managementIpAddress", data, role="operator"))

    def test_viewer_can_read_issue_summary(self):
        '''SR-1: viewer is allowed to receive issueSummary (public field)'''
        self.assertNotEqual([], json_search("issueSummary", data, role="viewer"))


if __name__ == '__main__':
    unittest.main()


