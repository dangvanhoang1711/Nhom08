from policy import POLICY


def _is_allowed(key, role):
    allowed_roles = POLICY.get(key)
    if allowed_roles is None:
        return True
    return role in allowed_roles


def json_search(key, input_object, role=None):
    """Recursively search `input_object` for every occurrence of `key`.

    All matches found in nested dicts and lists are aggregated into a list
    of single key/value dicts. Before any matched item is returned the
    `role` is checked against policy.POLICY: a role that is not allowed to
    read `key` (or a missing role on a protected key) is denied and an
    empty list is returned.
    """
    if not _is_allowed(key, role):
        return []

    ret_val = []
    if isinstance(input_object, dict):
        for current_key, value in input_object.items():
            if current_key == key:
                ret_val.append({current_key: value})
            if isinstance(value, (dict, list)):
                ret_val.extend(json_search(key, value, role))
    elif isinstance(input_object, list):
        for item in input_object:
            if isinstance(item, (dict, list)):
                ret_val.extend(json_search(key, item, role))
    return ret_val
