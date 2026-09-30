import unittest
from recursive_json_search import *
from test_data import *


class json_search_test(unittest.TestCase):
    '''test module to test search function `recursive_json_search.py`'''

    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([] != json_search(key1, data, role="viewer"))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data), list)

    def test_wrong_role_cannot_read_secret(self): 
        result = json_search("apiKey", data, role="viewer") 
        self.assertEqual([], result)

    def test_operator_cannot_read_api_key(self):
        result = json_search("apiKey", data, role="operator")
        self.assertEqual([], result)

    def test_viewer_cannot_read_management_ip_address(self):
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual([], result)

    def test_invalid_role_cannot_read_protected_data(self):
        result = json_search("apiKey", data, role="hacker")
        self.assertEqual([], result)

    def test_admin_can_read_api_key(self):
        result = json_search("apiKey", data, role="admin")
        self.assertEqual([{"apiKey": "SNMP-COMMUNITY-STRING-7f3a9c"}], result)

    def test_operator_can_read_management_ip_address(self):
        result = json_search("managementIpAddress", data, role="operator")
        self.assertEqual([{"managementIpAddress": "10.10.20.21"}], result)

    def test_viewer_can_read_issue_summary(self):
        result = json_search("issueSummary", data, role="viewer")
        self.assertEqual(
            [{"issueSummary": "Network Device 10.10.20.82 Is Unreachable From Controller"}],
            result,
        )



if __name__ == '__main__':
    unittest.main()