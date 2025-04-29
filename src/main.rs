#![allow(unused)]
use anyhow::{Result, bail};
use core::panic;
use log::debug;
use serde_json::{Map, Value, json};
use std::io;
use std::io::prelude::*;

use std::collections::HashSet;

pub fn merge_policies(
    ta_policies_in: &Value,
    ia_policies_in: &Value,
    n: &Value,
) -> Result<Map<String, Value>> {
    // Both the input has to be maps
    let ta_policies = ta_policies_in.as_object().unwrap();
    let ia_policies = ia_policies_in.as_object().unwrap();

    eprintln!("From TA: {:?}\n", ta_policies);
    eprintln!("From IA: {:?}\n", ia_policies);

    let mut merged: Map<String, Value> = Map::new();
    // FIXME: we assume both has the same keys
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
        let mut lres = Map::new();
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
            eprintln!("We have common {:?}", operator_name);
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
                    let mut ta_items = get_hashset_from_values(value_from_ta);
                    // For order
                    let ta_orderd_items = value_from_ta.as_array().unwrap();
                    let mut ia_items = get_hashset_from_values(value_from_ia);
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
                    let mut ta_items = get_hashset_from_values(value_from_ta);
                    let ta_orderd_items = value_from_ta.as_array().unwrap();
                    if ta_items.len() == 0 {
                        // It can not be empty
                        bail!("Policy error: TA one_of is empty");
                    }
                    let mut ia_items = get_hashset_from_values(value_from_ia);
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
            if let Some(default_op) = one_metadata_merged.get("default") {
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
            // Means we also have add
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

fn main() {
    let mut stdin = io::stdin();
    env_logger::init();
    let data = std::fs::read("metadata-policy-test-vectors-2025-02-13.json").unwrap();
    let data_str = std::str::from_utf8(&data).unwrap();
    let input: Value = serde_json::from_str(data_str).unwrap();

    for one_test in input.as_array().unwrap().iter() {
        let input_map = one_test.as_object().unwrap();
        let n = &input_map["n"];
        eprintln!("Running {}", n);
        let merged = merge_policies(&input_map["TA"], &input_map["INT"], n);
        match merged {
            Ok(m) => {
                eprintln!("Merged answer: {:?}\n\n", m);
                let expected = input_map.get("merged");
                match expected {
                    Some(exp) => {
                        let final_exp = exp.as_object().unwrap();

                        if (*final_exp != m) {
                            eprintln!("Expected answer: {:?}\n", final_exp);
                            panic!("Failed");
                        }
                    }
                    None => panic!("Missing merged output at {}", n),
                }
            }
            Err(e) => {
                let expected = input_map.get("error");
                match expected {
                    Some(exp) => (eprintln!("Received error in policy as expected\n")),
                    None => panic!("Missing error output at {}", n),
                }
            }
        }
        // Read a single byte and discard
        //let _ = stdin.read(&mut [0u8]).unwrap();
    }
}
