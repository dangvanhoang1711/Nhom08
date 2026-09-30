import unittest

from policy import POLICY
from recursive_json_search import json_search
from test_data import data, key1, key2


class json_search_test(unittest.TestCase):
    '''test module to test search function `recursive_json_search.py`'''

    # ---------- baseline functional tests ----------

    def test_search_found(self):
        '''key1 exists in the nested data, so a non-empty list with its value must be returned'''
        result = json_search(key1, data, role="viewer")
        self.assertNotEqual([], result)
        self.assertEqual(
            {key1: "Network Device 10.10.20.82 Is Unreachable From Controller"},
            result[0],
        )

    def test_search_not_found(self):
        '''key2 does not exist anywhere in the data, so an empty list must be returned'''
        self.assertEqual([], json_search(key2, data, role="admin"))

    def test_is_a_list(self):
        '''json_search must always return a list, found or not, allowed or denied'''
        self.assertIsInstance(json_search(key1, data, role="admin"), list)
        self.assertIsInstance(json_search(key2, data, role="admin"), list)
        self.assertIsInstance(json_search(key1, data), list)

    def test_search_aggregates_all_nested_matches(self):
        '''matches in nested dicts and lists must all be aggregated, none dropped'''
        result = json_search("message", data)
        self.assertEqual(4, len(result))
        for match in result:
            self.assertEqual(["message"], list(match.keys()))

    # ---------- security tests (policy.py / security-requirement.md) ----------

    def test_admin_can_read_api_key(self):
        '''SR-02: role admin is allowed to read the protected apiKey field'''
        self.assertEqual(
            [{"apiKey": "SNMP-COMMUNITY-STRING-7f3a9c"}],
            json_search("apiKey", data, role="admin"),
        )

    def test_operator_cannot_read_api_key(self):
        '''SR-02: operator is not in POLICY["apiKey"], so access must be denied'''
        self.assertEqual([], json_search("apiKey", data, role="operator"))

    def test_viewer_cannot_read_api_key(self):
        '''SR-02: viewer must never receive the SNMP community string'''
        self.assertEqual([], json_search("apiKey", data, role="viewer"))

    def test_admin_and_operator_can_read_management_ip(self):
        '''SR-03: admin and operator are allowed to read managementIpAddress'''
        expected = [{"managementIpAddress": "10.10.20.21"}]
        self.assertEqual(expected, json_search("managementIpAddress", data, role="admin"))
        self.assertEqual(expected, json_search("managementIpAddress", data, role="operator"))

    def test_viewer_cannot_read_management_ip(self):
        '''SR-03: viewer is not allowed to read managementIpAddress'''
        self.assertEqual([], json_search("managementIpAddress", data, role="viewer"))

    def test_all_allowed_roles_can_read_issue_summary(self):
        '''SR-04: admin, operator and viewer are all allowed to read issueSummary'''
        expected = [
            {key1: "Network Device 10.10.20.82 Is Unreachable From Controller"}
        ]
        for role in ("admin", "operator", "viewer"):
            self.assertEqual(expected, json_search(key1, data, role=role))

    def test_missing_role_is_denied_on_protected_keys(self):
        '''SR-05: omitting the role must fail closed for protected keys'''
        self.assertEqual([], json_search("apiKey", data))
        self.assertEqual([], json_search("managementIpAddress", data))

    def test_invalid_role_is_denied(self):
        '''SR-06: a role unknown to the policy must be denied on protected keys'''
        self.assertEqual([], json_search("apiKey", data, role="hacker"))
        self.assertEqual([], json_search("managementIpAddress", data, role="hacker"))

    def test_unprotected_key_is_readable_by_any_role(self):
        '''keys absent from POLICY are not access controlled and stay searchable'''
        self.assertNotEqual([], json_search("title", data, role="viewer"))
        self.assertNotEqual([], json_search("title", data))

    def test_policy_matrix_is_enforced(self):
        '''SR-07: every ALLOW/DENY entry declared in policy.POLICY must be enforced'''
        roles = sorted({role for allowed in POLICY.values() for role in allowed})
        for key, allowed_roles in POLICY.items():
            for role in roles:
                result = json_search(key, data, role=role)
                if role in allowed_roles:
                    self.assertNotEqual([], result, "%s must be allowed to read %s" % (role, key))
                else:
                    self.assertEqual([], result, "%s must be denied to read %s" % (role, key))


if __name__ == '__main__':
    unittest.main()
