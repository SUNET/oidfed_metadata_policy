use anyhow::{Result, bail};
use log::debug;
use serde_json::{Map, Value, json};

use std::collections::HashSet;

pub fn merge_policies(
    ta_policies_in: &Value,
    ia_policies_in: &Value,
) -> Result<Map<String, Value>> {
    // Both the input has to be maps
    let ta_policies = ta_policies_in.as_object().unwrap();
    let ia_policies = ia_policies_in.as_object().unwrap();

    debug!("From TA: {:?}\n", ta_policies);
    debug!("From IA: {:?}\n", ia_policies);

    let mut merged: Map<String, Value> = Map::new();
    for (oid_meta_name, value) in ta_policies.into_iter() {
        //debug!("metadata name {}", oid_meta_name);
        //debug!("metadata value {:?}\n", value);
        // First scenario when we have in TA but not in IA
        if !ia_policies.contains_key(oid_meta_name) {
            // directly copy over to merged
            merged.insert(oid_meta_name.clone(), value.clone());
            continue;
        }
        // For one metadata
        let mut one_metadata_merged = Map::new();
        // Means in both places
        let list_of_policies = value.as_object().unwrap();
        // oid_meata_name == "grant_type"
        // This will hold the details for oid_meta_names
        //let mut lres = Map::new();
        // First the ones in ta but not in ia
        let mut ta_names: HashSet<String> = HashSet::new();
        for name in list_of_policies.keys() {
            ta_names.insert(name.clone());
        }
        // We have all the names from ta
        let mut ia_names: HashSet<String> = HashSet::new();
        // values from the other list
        let list_from_ia = ia_policies.get(oid_meta_name).unwrap();
        let list_from_ia_policies = list_from_ia.as_object().unwrap();
        for name in list_from_ia_policies.keys() {
            ia_names.insert(name.clone());
        }
        // We have all the names from ia

        // Step 0, find the operators in ta but not in ia
        for x in ta_names.difference(&ia_names) {
            one_metadata_merged.insert(x.clone(), list_of_policies.get(x).unwrap().clone());
        }
        // Step 1 find the operators in ia but not in ta
        for x in ia_names.difference(&ta_names) {
            one_metadata_merged.insert(x.clone(), list_from_ia_policies.get(x).unwrap().clone());
        }
        // Step 2 the common operators
        for operator_name in ta_names.intersection(&ia_names) {
            // Means both the lists has the same operator
            // We have to deal by each operator here
            let value_from_ta = list_of_policies.get(operator_name).unwrap();
            let value_from_ia = list_from_ia_policies.get(operator_name).unwrap();
            debug!("From ta: {:?}", value_from_ta);
            debug!("From ia: {:?}", value_from_ia);
            let opname = operator_name.to_string();
            match opname.as_str() {
                "value" | "default" => {
                    // Both values should be the same
                    if value_from_ta == value_from_ia {
                        one_metadata_merged
                            .insert(operator_name.to_string(), value_from_ta.clone());
                    } else {
                        bail!(
                            "Policy error: {} is not the same in both side!",
                            operator_name
                        );
                    }
                }
                "add" => {
                    // Just add them into a new list
                    let ta_items = get_hashset_from_values(value_from_ta);
                    // For order
                    let ta_orderd_items = value_from_ta.as_array().unwrap();
                    let ia_items = get_hashset_from_values(value_from_ia);
                    // For order
                    let ia_orderd_items = value_from_ia.as_array().unwrap();
                    let added_items: HashSet<&Value> = ta_items.union(&ia_items).collect();

                    let mut result: Vec<&Value> = Vec::new();
                    // Loop through twice for order
                    for ta_o_i in ta_orderd_items.iter() {
                        if added_items.contains(ta_o_i) {
                            result.push(ta_o_i);
                        }
                    }
                    for ia_o_i in ia_orderd_items.iter() {
                        // This should be in union and not already added
                        if added_items.contains(ia_o_i) && !result.contains(&ia_o_i) {
                            result.push(ia_o_i);
                        }
                    }
                    one_metadata_merged.insert("add".to_string(), json!(result));
                }
                "one_of" => {
                    let ta_items = get_hashset_from_values(value_from_ta);
                    let ta_orderd_items = value_from_ta.as_array().unwrap();
                    if ta_items.len() == 0 {
                        // It can not be empty
                        bail!("Policy error: TA one_of is empty");
                    }
                    let ia_items = get_hashset_from_values(value_from_ia);
                    let ia_orderd_items = value_from_ia.as_array().unwrap();
                    if ia_items.len() == 0 {
                        // It can not be empty
                        bail!("Policy error: IA one_of is empty");
                    }
                    // There can not any item in ia which is not there in ta
                    // T > I
                    if ia_items.is_subset(&ta_items) {
                        let merged_value: HashSet<&Value> =
                            ta_items.intersection(&ia_items).collect();
                        // All good for IA
                        let result =
                            get_ordered_array(ta_orderd_items, ia_orderd_items, &merged_value);
                        one_metadata_merged.insert("one_of".to_string(), json!(result));
                    } else {
                        bail!("Policy error: IA has extra items in one_of");
                    }
                }
                "subset_of" => {
                    let ta_items = get_hashset_from_values(value_from_ta);
                    let ia_items = get_hashset_from_values(value_from_ia);
                    // There can not any item in ia which is not there in ta
                    // T > I

                    let merged_value: HashSet<&Value> = ta_items.intersection(&ia_items).collect();
                    //if ia_items.is_subset(&ta_items) {
                    //let merged_value: HashSet<&Value> =
                    //ta_items.intersection(&ia_items).collect();
                    //// All good for IA

                    one_metadata_merged.insert("subset_of".to_string(), json!(merged_value));
                    //} else {
                    //if n == 1510 {
                    //debug!("TA {:?}\n\nIA {:?}\n\n", ta_items, ia_items);
                    //}

                    //bail!("Policy error: IA has extra items in subset_of");
                    //}
                }
                "superset_of" => {
                    let ta_items = get_hashset_from_values(value_from_ta);
                    let ta_orderd_items = value_from_ta.as_array().unwrap();
                    let ia_items = get_hashset_from_values(value_from_ia);
                    let ia_orderd_items = value_from_ia.as_array().unwrap();
                    // There can not any item in ta which is not there in ia
                    // T < I
                    if ta_items.is_subset(&ia_items) {
                        // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.6-10
                        let merged_value: HashSet<&Value> = ta_items.union(&ia_items).collect();
                        // All good for IA
                        let result =
                            get_ordered_array(ta_orderd_items, ia_orderd_items, &merged_value);
                        one_metadata_merged.insert("superset_of".to_string(), json!(result));
                    } else {
                        bail!("Policy error: IA has extra items in subset_of");
                    }
                }
                "essential" => {
                    let ta_item = value_from_ta.as_bool().unwrap();
                    let ia_item = value_from_ia.as_bool().unwrap();
                    one_metadata_merged.insert("essential".to_string(), json!(ta_item || ia_item));
                }

                // TODO: https://openid.net/specs/openid-federation-1_0.html#name-additional-operators
                // Not sure what to do with these in future
                _ => (),
            }
        }
        // Now we have to verify each of the operator if they are allowed
        if let Some(value_op) = one_metadata_merged.get("value") {
            let operator_value_hash = get_hashset_from_values(value_op);
            // Means we also have add
            if let Some(add_op) = one_metadata_merged.get("add") {
                let add_value_hash = get_hashset_from_values(add_op);
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.1.1
                if !add_value_hash.is_subset(&operator_value_hash) {
                    // error
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate grant_types policy: Illegal value \/ add operator combination: The add must be a subset of the values of value"
                    );
                }
            }

            // Means we also have default
            if let Some(_default_op) = one_metadata_merged.get("default") {
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.2.1
                // Value should not be null
                if value_op.is_null() {
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate logo_uri policy: Illegal value \/ default operator combination: The value must be non-null"
                    );
                }
            }

            // Means we also have one_of
            if let Some(one_of_op) = one_metadata_merged.get("one_of") {
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.3.1
                // Value must be among the one_of value
                let one_of_value_hash = get_hashset_from_values(one_of_op);
                if !operator_value_hash.is_subset(&one_of_value_hash) {
                    debug!("{:?}", operator_value_hash);
                    debug!("{:?}", one_of_value_hash);
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate logo_uri policy: Illegal value \/ one_of operator combination: The value must be among the one_of values"
                    );
                }
            }

            // Means we also have superset_of
            if let Some(superset_of_op) = one_metadata_merged.get("superset_of") {
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.5.1

                // Value must be superset_of superset
                let superset_of_value_hash = get_hashset_from_values(&superset_of_op);

                if !superset_of_value_hash.is_subset(&operator_value_hash) {
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate grant_types policy: Illegal value \/ superset_of operator combination: The value must be a superset of the values of superset_of"
                    );
                }
            }
            // Means we also have subset_of
            if let Some(subset_of_op) = one_metadata_merged.get("subset_of") {
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.4.1
                // Value must be subset_of subset
                let subset_of_value_hash = get_hashset_from_values(&subset_of_op);

                if !operator_value_hash.is_subset(&subset_of_value_hash) {
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate grant_types policy: Illegal value \/ subset_of operator combination: The value must be a subset of the values of subset_of"
                    );
                }
            }
            // Means we also have essential
            if let Some(essential_op) = one_metadata_merged.get("essential") {
                //https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.6.1
                // Value should not be null
                let es_val = essential_op.as_bool().unwrap();
                if es_val && value_op.is_null() {
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate logo_uri policy: Illegal value \/ essential operator combination: The value must be non-null when essential is true"
                    );
                }
            }
        }
        if let Some(add_op) = one_metadata_merged.get("add") {
            let operator_add_hash = get_hashset_from_values(add_op);
            // Means we also have subset
            if let Some(subset_op) = one_metadata_merged.get("subset_of") {
                let subset_hash = get_hashset_from_values(subset_op);
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.1.1
                if !operator_add_hash.is_subset(&subset_hash) {
                    // error
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate grant_types policy: Illegal subset_of \/ add operator combination: The values of add must be a subset of the values of subset_of"
                    );
                }
            }
        }
        if let Some(subset_op) = one_metadata_merged.get("subset_of") {
            let operator_subset_hash = get_hashset_from_values(subset_op);
            // Means we also have superset_of
            if let Some(superset_op) = one_metadata_merged.get("superset_of") {
                let superset_hash = get_hashset_from_values(superset_op);
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.5-8.4.1
                if !superset_hash.is_subset(&operator_subset_hash) {
                    // error
                    bail!(
                        r"Subordinate policy merge error: Illegal subordinate grant_types policy: Illegal subset_of \/ superset_of operator combination: The values of subset_of must be a superset of the values of superset_of"
                    );
                }
            }
        }

        // We are done for one metadata, merge it to final answer
        merged.insert(oid_meta_name.to_string(), json!(one_metadata_merged));
    }

    // Now loop
    Ok(merged)
}

pub fn get_ordered_array(
    ta_orderd_items: &Vec<Value>,
    ia_orderd_items: &Vec<Value>,
    added_items: &HashSet<&Value>,
) -> Value {
    let mut result: Vec<&Value> = Vec::new();
    // Loop through twice for order
    for ta_o_i in ta_orderd_items.iter() {
        if added_items.contains(ta_o_i) {
            result.push(ta_o_i);
        }
    }
    for ia_o_i in ia_orderd_items.iter() {
        // This should be in union and not already added
        if added_items.contains(ia_o_i) && !result.contains(&ia_o_i) {
            result.push(ia_o_i);
        }
    }
    return json!(result);
}

pub fn get_hashset_from_values(values: &Value) -> HashSet<Value> {
    let mut hash_set = HashSet::new();
    if values.is_array() {
        let internal = values.as_array().unwrap();
        for v in internal.iter() {
            hash_set.insert(v.clone());
        }
    } else {
        hash_set.insert(values.clone());
    }
    hash_set
}

pub fn is_subset_of(val: &Value, val2: &Value) -> bool {
    let v1 = get_hashset_from_values(&val);
    let v2 = get_hashset_from_values(&val2);
    v1.is_subset(&v2)
}

pub fn is_superset_of(val: &Value, val2: &Value) -> bool {
    let v1 = get_hashset_from_values(&val);
    let v2 = get_hashset_from_values(&val2);
    v2.is_subset(&v1)
}

pub fn intersection_of(val: &Value, val2: &Value) -> Option<HashSet<Value>> {
    let mut result: HashSet<Value> = HashSet::new();
    let v1 = get_hashset_from_values(&val);
    let v2 = get_hashset_from_values(&val2);
    for x in v1.intersection(&v2) {
        result.insert(x.clone());
    }
    Some(result.clone())
}

pub fn get_hashset_from_only_names(values: &Value) -> HashSet<Value> {
    let mut hash_set = HashSet::new();
    if values.is_array() {
        let internal = values.as_array().unwrap();
        for v in internal.iter() {
            hash_set.insert(v.clone());
        }
    } else if values.is_object() {
        for v in values.as_object().unwrap().keys() {
            hash_set.insert(json!(v));
        }
    } else {
        hash_set.insert(values.clone());
    }
    hash_set
}

pub fn resolve_metadata_policy(
    policy: &Map<String, Value>,
    metadata: &Map<String, Value>,
) -> Result<Value> {
    debug!("--IN RESOLVE FUNCTION--\n");
    debug!("\npolicy: {:?}", policy);
    debug!("\nmetadata {:?}\n", metadata);
    let mut result = Map::new();
    for (metadata_name, metadata_value) in metadata.iter() {
        // To check if policy has same key, if not then add it directly and move on to next
        // metadata
        if !policy.contains_key(metadata_name) {
            result.insert(metadata_name.to_string(), metadata_value.clone());
            continue;
        }
        // If we are here means we have a corresponding policy
        let policy_value = policy.get(metadata_name).unwrap().as_object().unwrap();
        debug!(
            "\npolicy_value {:?} and metadata_value {:?}",
            policy_value, metadata_value
        );

        // First check value
        if policy_value.contains_key("value") {
            // THis has highest priority
            let value_data = policy_value.get("value").unwrap();
            if !value_data.is_null() {
                result.insert(metadata_name.to_owned(), value_data.clone());
            }
            continue;
        }
        // Now add
        let mut internal_result = Map::new();
        let mut local_result_flag = false;
        if let Some(policy_value_data) = policy_value.get("add") {
            debug!("\nWe have ADD in POLICY: {:?}\n", policy_value_data);
            let mut iresult = Vec::new();
            // we have both add and metadata value
            let mvalue = metadata_value.as_array().unwrap();
            for v in mvalue.iter() {
                iresult.push(v);
            }
            debug!("Copied all metadata in iresult: {:?}\n", iresult);
            for v in policy_value_data.as_array().unwrap().iter() {
                // Don't add if we already added
                if !iresult.contains(&v) {
                    iresult.push(v);
                }
            }
            debug!("Copied all policy in iresult: {:?}\n", iresult);

            internal_result.insert("final".to_string(), json!(iresult.clone()));
            local_result_flag = true;
        }
        // default
        // This does not make any sense here as we have a value in metadata
        if let Some(policy_value_data) = policy_value.get("default") {
            debug!("\nWe have DEFAULT in POLICY: {:?}\n", policy_value_data);
            // If already created local internal result, then we don't have to do anything
            // else the current metadata provided value is the internal data
            if !local_result_flag {
                internal_result.insert("final".to_string(), metadata_value.clone());
            }
        }

        // one_of
        let mut one_of_flag = false;
        if let Some(policy_value_data) = policy_value.get("one_of") {
            debug!("\nWe have ONE_OF in POLICY: {:?}\n", policy_value_data);
            let vec_policy = policy_value_data.as_array().unwrap();
            if vec_policy.contains(&metadata_value) {
                internal_result.insert("final".to_string(), metadata_value.clone());
                one_of_flag = true;
            }
            // A single object, can not be a list
            else {
                // the given value is not in one_of
                bail!("Failed to find in one_of")
            }
        }
        if !one_of_flag {
            // if not one_of then only we should check subset and superset
            if let Some(policy_value_data) = policy_value.get("subset_of") {
                // Now if we have final means already applied result
                let current_value = match internal_result.contains_key("final") {
                    true => internal_result.get("final").unwrap().clone(),
                    false => metadata_value.clone(),
                };
                debug!("SUBSET: {:?} and {:?}", policy_value_data, current_value);
                if is_subset_of(&current_value, policy_value_data) {
                    internal_result.insert("final".to_string(), current_value.clone());
                }
                if let Some(middle_data) =
                    intersection_of(policy_value_data, &current_value.clone())
                {
                    if middle_data.len() > 0 {
                        internal_result.insert("final".to_string(), json!(middle_data));
                    } else {
                        let empty_vec: Vec<String> = Vec::new();
                        // Means nothing common, it should become empty list
                        internal_result.insert("final".to_string(), json!(empty_vec));
                    }
                }
            }
            if let Some(policy_value_data) = policy_value.get("superset_of") {
                // let vec_policy = policy_value_data.as_array().unwrap();
                // Now if we have final means already applied result
                let current_value = match internal_result.contains_key("final") {
                    true => internal_result.get("final").unwrap(),
                    false => metadata_value,
                };
                debug!("SUPERSET: {:?} and {:?}", policy_value_data, current_value);
                if is_subset_of(policy_value_data, &current_value) {
                    internal_result.insert("final".to_string(), current_value.clone());
                }
                // A single object, can not be a list
                else {
                    // the given value is not in one_of
                    bail!("superset_of failed")
                }
            }
        }
        debug!("internal_result {:?}\n", internal_result);
        result.insert(
            metadata_name.to_string(),
            internal_result.get("final").unwrap().clone(),
        );
    }
    // Now for the things in policy but not on metadata
    //let policy_hash = get_hashset_from_values(&json!(&policy));
    let policy_hash = json!(policy).as_object().unwrap().clone();
    let policy_hash_names = get_hashset_from_only_names(&json!(&policy));
    let metadata_hash = get_hashset_from_values(&json!(&metadata));
    let metadata_hash_names = get_hashset_from_only_names(&json!(&metadata));
    debug!(
        "Before only_policy: {:?} {:?}\n",
        policy_hash, metadata_hash
    );
    for x in policy_hash_names.difference(&metadata_hash_names) {
        let mkey = x.as_str().unwrap();
        let mvalue = policy_hash
            .get(x.as_str().unwrap())
            .unwrap()
            .as_object()
            .unwrap();
        // This is the name of the metadata
        // If we have a value, then that is the answer
        if mvalue.contains_key("value") {
            debug!("0metadata: FOUND VALUE IN POLICY");

            let value_data = mvalue.get("value").unwrap();
            if !value_data.is_null() {
                result.insert(mkey.to_owned(), value_data.clone());
            }
            //result.insert(mkey.to_owned(), mvalue.get("value").unwrap().clone());
            continue;
        }
        // to know if we already  made a new metadata value from add or default
        let mut new_metadata_flag = false;
        if mvalue.contains_key("add") {
            debug!("0metadata: FOUND ADD IN POLICY");
            result.insert(mkey.to_owned(), mvalue.get("add").unwrap().clone());
            new_metadata_flag = true;
            //continue;
        }
        if mvalue.contains_key("default") && new_metadata_flag == false {
            debug!("0metadata: FOUND DEFAULT IN POLICY");
            result.insert(mkey.to_owned(), mvalue.get("default").unwrap().clone());
            new_metadata_flag = true;
        }

        let mut empty_subset_found = false;
        if mvalue.contains_key("subset_of") {
            debug!("0metadata: FOUND SUBSET_OF IN POLICY");
            if new_metadata_flag {
                let policy_value_data = mvalue.get("subset_of").unwrap();
                let current_result = result.get(mkey).unwrap();
                let local_result = intersection_of(current_result, policy_value_data).unwrap();
                result.insert(mkey.to_owned(), json!(local_result));
            } else {
                empty_subset_found = true;
                new_metadata_flag = true
            }
            //else {
            //let empty_vec: Vec<String> = Vec::new();
            //result.insert(mkey.to_owned(), json!(empty_vec));
            //}
        }

        if mvalue.contains_key("superset_of") {
            debug!("0metadata: FOUND SUPERSET_OF IN POLICY");
            if new_metadata_flag {
                let policy_value_data = mvalue.get("superset_of").unwrap();
                let is_super = if empty_subset_found {
                    // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.6-2
                    // If we reached here, means we had a subset_of and after applying we have an
                    // empty list as result. Which we don't even store in the result variable.
                    //let empty_vec: Vec<String> = Vec::new();
                    //let current_result = json!(empty_vec);
                    //debug!(
                    //"\nTO empty calculation ===> {:?} IN {:?}",
                    //current_result, policy_value_data
                    //);
                    //is_superset_of(&current_result, policy_value_data)
                    true
                } else {
                    let current_result = result.get(mkey).unwrap();
                    debug!(
                        "\nTO calculation ===> {:?} IN {:?}",
                        current_result, policy_value_data
                    );
                    is_superset_of(current_result, policy_value_data)
                };
                if !is_super {
                    // Means we have a failure
                    //https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.6-2
                    bail!("default/add value is not superset_of value")
                }
            }
            //else {
            //bail!("we have superset_of in policy but no default/add value");
            //}
        }

        if mvalue.contains_key("essential") {
            if empty_subset_found == true {
                bail!("We have an essential policy but empty subset");
            }
            if new_metadata_flag == false {
                bail!("We have an essential policy but not metadata");
            }
        }
    }

    Ok(json!(result))
}

pub fn check_equal(v1: &Value, v2: &Value) -> bool {
    // Check two values are same using unordered sets
    let v1 = v1.as_object().unwrap();
    let v2 = v2.as_object().unwrap();
    // First let us check if we have the same keys in both places
    let mut k1: HashSet<&String> = HashSet::new();
    for x in v1.keys() {
        k1.insert(x);
    }
    let mut k2: HashSet<&String> = HashSet::new();
    for x in v2.keys() {
        k2.insert(x);
    }
    if k1 != k2 {
        return false;
    }
    for name in v1.keys() {
        let h1 = get_hashset_from_values(v1.get(name).unwrap());
        let h2 = get_hashset_from_values(v2.get(name).unwrap());
        if h1 != h2 {
            return false;
        }
    }
    true
}
