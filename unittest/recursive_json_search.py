from policy import POLICY


def json_search(key, input_object, role=None):
    ret_val=[]

    if isinstance(input_object, dict):
        for current_key, value in input_object.items():
            if current_key == key:
                allowed_roles = POLICY.get(key)
                if allowed_roles is None or role in allowed_roles:
                    ret_val.append({current_key: value})

            if isinstance(value, (dict, list)):
                ret_val.extend(json_search(key, value, role))

    elif isinstance(input_object, list):
        for value in input_object:
            if isinstance(value, (dict, list)):
                ret_val.extend(json_search(key, value, role))

    return ret_val