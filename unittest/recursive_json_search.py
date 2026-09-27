# Fill the Python code in this file
from test_data import * 
from policy import POLICY
def json_search(key, input_object, role=None): 
    ret_val=[] 
    if isinstance(input_object, dict): # Iterate dictionary 
        for k, v in input_object.items(): # searching key in the dict 
            if k == key: 
                allowed_roles = POLICY.get(k, [])
                if role in allowed_roles:
                    temp = {k: v}
                    ret_val.append(temp)
            if isinstance(v, dict): # the value is another dict so repeat 
                ret_val.extend(json_search(key, v, role=role)) 
            elif isinstance(v, list): # it's a list 
                for item in v: 
                    if not isinstance(item, (str,int)): # if dict or list repeat 
                        ret_val.extend(json_search(key,item, role=role)) 
    else: # Iterate a list because some APIs return JSON object in a list 
        for val in input_object: 
            if not isinstance(val, (str,int)): 
                ret_val.extend(json_search(key, val, role=role)) 
    return ret_val 

print(json_search("issueSummary", data, role="admin"))


