//! # OpenID Federation Metadata Policy
//!
//! This crate implements metadata policy operations for OpenID Federation as specified in
//! [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html).
//!
//! It provides functionality to:
//! - Merge metadata policies from Trust Anchors and Intermediate Authorities
//! - Apply metadata policies to entity metadata
//! - Resolve metadata according to policy constraints
//!
//! ## Example
//!
//! ```rust
//! use serde_json::json;
//!
//! let metadata = json!({
//!     "openid_relying_party": {
//!         "application_type": "web",
//!         "grant_types": ["authorization_code", "implicit"]
//!     }
//! });
//!
//! let full_policy = json!({
//!     "metadata_policy": {},
//!     "metadata": {
//!         "openid_relying_party": {
//!             "application_type": "native"
//!         }
//!     }
//! });
//!
//! let result = oidfed_metadata_policy::apply_policy_document_on_metadata(
//!     full_policy.as_object().unwrap(),
//!     metadata.as_object().unwrap()
//! ).unwrap();
//!
//! assert_eq!(result["openid_relying_party"]["application_type"], "native");
//! assert_eq!(result["openid_relying_party"]["grant_types"], json!(["authorization_code", "implicit"]));
//! ```

use anyhow::{Result, bail};
use log::debug;
use serde_json::{Map, Value, json};

use std::collections::HashSet;

/// Merges a Trust Anchor's (TA) policy on top of an Intermediate Authority's (IA) policy
/// according to the OpenID Federation policy merging rules.
///
/// This function implements the policy merge algorithm defined in
/// [Section 6.1.3](https://openid.net/specs/openid-federation-1_0.html#section-6.1.3)
/// of the OpenID Federation specification.
///
/// # Arguments
///
/// * `ta_policies_in` - The Trust Anchor's metadata policy as a JSON value
/// * `ia_policies_in` - The Intermediate Authority's metadata policy as a JSON value
///
/// # Returns
///
/// Returns `Ok(Map<String, Value>)` containing the merged policy, or an `Err` if
/// the policies cannot be merged due to conflicts.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let ta_policy = json!({
///     "openid_relying_party": {
///         "grant_types": {
///             "subset_of": ["authorization_code", "implicit"]
///         }
///     }
/// });
///
/// let ia_policy = json!({
///     "openid_relying_party": {
///         "grant_types": {
///             "subset_of": ["authorization_code", "implicit", "client_credentials"]
///         }
///     }
/// });
///
/// let merged = oidfed_metadata_policy::merge_policies(&ta_policy, &ia_policy).unwrap();
/// // The merged policy will have the intersection of subset_of values
/// ```
pub fn merge_policies(
    ta_policies_in: &Value,
    ia_policies_in: &Value,
) -> Result<Map<String, Value>> {
    // This will hold the final merge result
    let mut merged: Map<String, Value> = Map::new();
    let m1: Map<String, Value> = Map::new();
    let m2: Map<String, Value> = Map::new();
    let tapolicies: &Map<String, Value> = ta_policies_in.as_object().unwrap_or(&m1);
    let iapolicies: &Map<String, Value> = ia_policies_in.as_object().unwrap_or(&m2);

    // First check all the entity types in ia
    for (oidf_entity_type, value) in iapolicies.into_iter() {
        if !tapolicies.contains_key(oidf_entity_type) {
            // Directly copy over
            merged.insert(oidf_entity_type.clone(), value.clone());
            continue;
        }
        // If we are here, means that entity_type is in both policies
        let inta = tapolicies.get(oidf_entity_type).unwrap();
        let m = merge_one_type_policy(inta, value)?;
        merged.insert(oidf_entity_type.clone(), json!(m));
    }

    // Now for the enity types in TA but not in IA.
    for (oidf_entity_type, value) in tapolicies.into_iter() {
        if !iapolicies.contains_key(oidf_entity_type) {
            // Directly copy over
            merged.insert(oidf_entity_type.clone(), value.clone());
            continue;
        }
    }

    Ok(merged)
}

/// Merges metadata policies for a single entity type from Trust Anchor and Intermediate Authority.
///
/// This function handles the detailed merging logic for individual policy operators such as
/// `value`, `default`, `add`, `one_of`, `subset_of`, `superset_of`, and `essential`.
///
/// The merge follows the rules defined in
/// [Section 6.1.3.1](https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1)
/// of the OpenID Federation specification.
///
/// # Arguments
///
/// * `ta_policies_in` - The Trust Anchor's policy for one entity type
/// * `ia_policies_in` - The Intermediate Authority's policy for the same entity type
///
/// # Returns
///
/// Returns `Ok(Map<String, Value>)` with the merged policy, or `Err` if policies conflict.
///
/// # Errors
///
/// Returns an error if:
/// - `value` or `default` operators have different values in TA and IA
/// - `one_of` in IA contains values not present in TA's `one_of`
/// - `superset_of` in TA is not a subset of IA's `superset_of`
/// - Combined operators violate policy constraints
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let ta_policy = json!({
///     "grant_types": {
///         "subset_of": ["authorization_code", "implicit"]
///     }
/// });
///
/// let ia_policy = json!({
///     "grant_types": {
///         "default": ["authorization_code"]
///     }
/// });
///
/// let merged = oidfed_metadata_policy::merge_one_type_policy(&ta_policy, &ia_policy).unwrap();
/// ```
pub fn merge_one_type_policy(
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
                    if ta_items.is_empty() {
                        // It can not be empty
                        bail!("Policy error: TA one_of is empty");
                    }
                    let ia_items = get_hashset_from_values(value_from_ia);
                    let ia_orderd_items = value_from_ia.as_array().unwrap();
                    if ia_items.is_empty() {
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
                        r"Subordinate policy merge error: the add must be a subset of the values of value"
                    );
                }
            }

            // Means we also have default
            if let Some(_default_op) = one_metadata_merged.get("default") {
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.2.1
                // Value should not be null
                if value_op.is_null() {
                    bail!(r"Subordinate policy merge error: the value must be non-null");
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
                        r"Subordinate policy merge error: The value must be among the one_of values"
                    );
                }
            }

            // Means we also have superset_of
            if let Some(superset_of_op) = one_metadata_merged.get("superset_of") {
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.5.1

                // Value must be superset_of superset
                let superset_of_value_hash = get_hashset_from_values(superset_of_op);

                if !superset_of_value_hash.is_subset(&operator_value_hash) {
                    bail!(
                        r"Subordinate policy merge error: The value must be a superset of the values of superset_of"
                    );
                }
            }
            // Means we also have subset_of
            if let Some(subset_of_op) = one_metadata_merged.get("subset_of") {
                // https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1.1-8.4.1
                // Value must be subset_of subset
                let subset_of_value_hash = get_hashset_from_values(subset_of_op);

                if !operator_value_hash.is_subset(&subset_of_value_hash) {
                    bail!(
                        r"Subordinate policy merge error: The value must be a subset of the values of subset_of"
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
                        r"Subordinate policy merge error: The value must be non-null when essential is true"
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
                        r"Subordinate policy merge error: The values of add must be a subset of the values of subset_of"
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
                        r"Subordinate policy merge error: The values of subset_of must be a superset of the values of superset_of"
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

/// Returns an ordered array by merging items from Trust Anchor and Intermediate Authority.
///
/// This helper function maintains the order of items when merging policy values,
/// prioritizing items from the Trust Anchor's order first, then adding remaining
/// items from the Intermediate Authority.
///
/// # Arguments
///
/// * `ta_orderd_items` - Ordered slice of values from the Trust Anchor
/// * `ia_orderd_items` - Ordered slice of values from the Intermediate Authority
/// * `added_items` - Set of items that should be included in the result
///
/// # Returns
///
/// A JSON array value containing the ordered merged items.
///
/// # Example
///
/// ```rust
/// use serde_json::{json, Value};
/// use std::collections::HashSet;
///
/// let ta_items = vec![json!("a"), json!("b")];
/// let ia_items = vec![json!("b"), json!("c")];
/// let a = json!("a");
/// let b = json!("b");
/// let c = json!("c");
/// let added: HashSet<&Value> = [&a, &b, &c].into_iter().collect();
///
/// let result = oidfed_metadata_policy::get_ordered_array(&ta_items, &ia_items, &added);
/// // Result: ["a", "b", "c"] - TA order preserved, then IA items added
/// ```
pub fn get_ordered_array(
    ta_orderd_items: &[Value],
    ia_orderd_items: &[Value],
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
    json!(result)
}

/// Converts a JSON value into a `HashSet` of values.
///
/// If the input is an array, each element becomes a set member.
/// If the input is a single value, it becomes the only member of the set.
///
/// # Arguments
///
/// * `values` - A JSON value (array or single value)
///
/// # Returns
///
/// A `HashSet<Value>` containing the values.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let array = json!(["a", "b", "c"]);
/// let set = oidfed_metadata_policy::get_hashset_from_values(&array);
/// assert_eq!(set.len(), 3);
///
/// let single = json!("a");
/// let set = oidfed_metadata_policy::get_hashset_from_values(&single);
/// assert_eq!(set.len(), 1);
/// ```
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

/// Checks if the first value is a subset of the second value.
///
/// Both values are converted to sets before comparison. Works with both
/// single values and arrays.
///
/// # Arguments
///
/// * `val` - The value to check if it's a subset
/// * `val2` - The value to check against (superset candidate)
///
/// # Returns
///
/// `true` if `val` is a subset of `val2`, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let subset = json!(["a", "b"]);
/// let superset = json!(["a", "b", "c"]);
///
/// assert!(oidfed_metadata_policy::is_subset_of(&subset, &superset));
/// assert!(!oidfed_metadata_policy::is_subset_of(&superset, &subset));
/// ```
pub fn is_subset_of(val: &Value, val2: &Value) -> bool {
    let v1 = get_hashset_from_values(val);
    let v2 = get_hashset_from_values(val2);
    v1.is_subset(&v2)
}

/// Checks if the first value is a superset of the second value.
///
/// Both values are converted to sets before comparison. Works with both
/// single values and arrays.
///
/// # Arguments
///
/// * `val` - The value to check if it's a superset
/// * `val2` - The value to check against (subset candidate)
///
/// # Returns
///
/// `true` if `val` is a superset of `val2`, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let superset = json!(["a", "b", "c"]);
/// let subset = json!(["a", "b"]);
///
/// assert!(oidfed_metadata_policy::is_superset_of(&superset, &subset));
/// assert!(!oidfed_metadata_policy::is_superset_of(&subset, &superset));
/// ```
pub fn is_superset_of(val: &Value, val2: &Value) -> bool {
    let v1 = get_hashset_from_values(val);
    let v2 = get_hashset_from_values(val2);
    v2.is_subset(&v1)
}

/// Computes the intersection of two JSON values as sets.
///
/// Both values are converted to sets and the intersection is returned.
///
/// # Arguments
///
/// * `val` - First JSON value
/// * `val2` - Second JSON value
///
/// # Returns
///
/// `Some(HashSet<Value>)` containing the intersection of both values.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let v1 = json!(["a", "b", "c"]);
/// let v2 = json!(["b", "c", "d"]);
///
/// let result = oidfed_metadata_policy::intersection_of(&v1, &v2).unwrap();
/// assert_eq!(result.len(), 2); // Contains "b" and "c"
/// ```
pub fn intersection_of(val: &Value, val2: &Value) -> Option<HashSet<Value>> {
    let mut result: HashSet<Value> = HashSet::new();
    let v1 = get_hashset_from_values(val);
    let v2 = get_hashset_from_values(val2);
    for x in v1.intersection(&v2) {
        result.insert(x.clone());
    }
    Some(result.clone())
}

/// Extracts only the names (keys) from a JSON value into a `HashSet`.
///
/// For objects, extracts the keys. For arrays, extracts the elements.
/// For single values, creates a set with just that value.
///
/// # Arguments
///
/// * `values` - A JSON value (object, array, or single value)
///
/// # Returns
///
/// A `HashSet<Value>` containing the names/keys.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let obj = json!({"key1": "value1", "key2": "value2"});
/// let names = oidfed_metadata_policy::get_hashset_from_only_names(&obj);
/// assert_eq!(names.len(), 2);
/// assert!(names.contains(&json!("key1")));
/// ```
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

/// Resolves metadata according to a given policy.
///
/// This function applies policy operators to metadata values and returns the
/// resolved metadata. It handles operators like `value`, `add`, `default`,
/// `one_of`, `subset_of`, `superset_of`, and `essential`.
///
/// # Arguments
///
/// * `policy` - The metadata policy containing operators for each metadata field
/// * `metadata` - The original metadata to apply the policy to
///
/// # Returns
///
/// Returns `Ok(Value)` with the resolved metadata, or `Err` if the metadata
/// violates the policy constraints.
///
/// # Errors
///
/// Returns an error if:
/// - A value is not in the `one_of` list
/// - A value is not a superset of `superset_of` requirement
/// - An essential field is missing or has an empty value
///
/// # Example
///
/// ```rust
/// use serde_json::{json, Map, Value};
///
/// let policy: Map<String, Value> = json!({
///     "grant_types": {
///         "default": ["authorization_code"]
///     }
/// }).as_object().unwrap().clone();
///
/// let metadata: Map<String, Value> = json!({
///     "client_name": "My App"
/// }).as_object().unwrap().clone();
///
/// let resolved = oidfed_metadata_policy::resolve_metadata_policy(&policy, &metadata).unwrap();
/// // grant_types will have the default value since it wasn't in metadata
/// ```
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
            if vec_policy.contains(metadata_value) {
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
                    if !middle_data.is_empty() {
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
                if is_subset_of(policy_value_data, current_value) {
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
        if mvalue.contains_key("default") && !new_metadata_flag {
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
            if empty_subset_found {
                bail!("We have an essential policy but empty subset");
            }
            if !new_metadata_flag {
                bail!("We have an essential policy but not metadata");
            }
        }
    }

    Ok(json!(result))
}

/// Checks if two JSON values are equal using unordered set comparison.
///
/// This function compares two JSON objects by checking if they have the same keys
/// and if the values for each key are equal when treated as sets (order-independent).
///
/// # Arguments
///
/// * `v1` - First JSON value to compare (must be an object)
/// * `v2` - Second JSON value to compare (must be an object)
///
/// # Returns
///
/// `true` if both values have the same keys and equal values (as sets), `false` otherwise.
///
/// # Panics
///
/// Panics if either value is not a JSON object.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let v1 = json!({
///     "grant_types": ["authorization_code", "implicit"],
///     "application_type": "web"
/// });
///
/// let v2 = json!({
///     "application_type": "web",
///     "grant_types": ["implicit", "authorization_code"]  // Different order, same values
/// });
///
/// assert!(oidfed_metadata_policy::check_equal(&v1, &v2));
///
/// let v3 = json!({
///     "grant_types": ["authorization_code"],
///     "application_type": "web"
/// });
///
/// assert!(!oidfed_metadata_policy::check_equal(&v1, &v3));
/// ```
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

/// Applies the forced metadata from a subordinate statement to the metadata of the entity.
///
/// This is an internal helper function that merges forced metadata values into
/// the entity's existing metadata for a specific entity type.
fn apply_forced_metadata(
    kind: &str,
    metadata: &Map<String, Value>,
    forced_meta: &Map<String, Value>,
) -> Map<String, Value> {
    let mut meta = metadata.get(kind).unwrap().as_object().unwrap().clone();
    match forced_meta.contains_key(kind) {
        false => meta,
        true => {
            let forced_meta_details: &Map<String, Value> =
                forced_meta.get(kind).unwrap().as_object().unwrap();
            // means we need to apply the forced metadata
            for (fmetadata_name, fmetadata_value) in forced_meta_details.iter() {
                meta.insert(fmetadata_name.clone(), fmetadata_value.clone());
            }
            meta
        }
    }
}

/// Applies a full policy document on the raw metadata of a given entity.
///
/// This function processes a complete policy document (containing `metadata_policy` and
/// optional `metadata` for forced values) and applies it to entity metadata. It handles
/// multiple entity types including `openid_relying_party`, `openid_provider`,
/// `federation_entity`, `oauth_client`, `oauth_authorization_server`, and `oauth_resource`.
///
/// The function first applies any forced metadata values, then applies the metadata policy
/// constraints for each entity type present in the input metadata.
///
/// # Arguments
///
/// * `full_policy` - The complete policy document containing:
///   - `metadata_policy`: Policy operators for each entity type
///   - `metadata`: Forced metadata values to override (optional)
/// * `metadata` - The original entity metadata organized by entity type
///
/// # Returns
///
/// Returns `Ok(Map<String, Value>)` containing the resolved metadata for all entity types,
/// or `Err` if policy constraints are violated.
///
/// # Errors
///
/// Returns an error if:
/// - No known entity type is found in the metadata
/// - Policy constraints (e.g., `superset_of`, `one_of`) are violated
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// let metadata = json!({
///     "openid_relying_party": {
///         "application_type": "web",
///         "grant_types": ["authorization_code", "implicit"]
///     }
/// });
///
/// let full_policy = json!({
///     "metadata_policy": {
///         "openid_relying_party": {
///             "grant_types": {
///                 "subset_of": ["authorization_code", "implicit", "client_credentials"]
///             }
///         }
///     },
///     "metadata": {
///         "openid_relying_party": {
///             "application_type": "native"  // Force this value
///         }
///     }
/// });
///
/// let result = oidfed_metadata_policy::apply_policy_document_on_metadata(
///     full_policy.as_object().unwrap(),
///     metadata.as_object().unwrap()
/// ).unwrap();
///
/// // application_type is now "native" (forced)
/// assert_eq!(result["openid_relying_party"]["application_type"], "native");
/// ```
///
/// # Additional Examples
///
/// See the integration tests in [`tests/apply_policy.rs`] for more comprehensive examples:
///
/// - `test_apply_blank_policy` - Applying empty policy with forced metadata
/// - `test_apply_policy_superset_failure` - Error handling when `superset_of` constraint fails
/// - `test_apply_policy_subset_of_without_metadata` - Using `subset_of` without forced metadata
/// - `test_apply_policy_subset_of_with_metadata` - Combining `subset_of` with forced metadata
///
/// [`tests/apply_policy.rs`]: https://github.com/user/oidfed_metadata_policy/blob/main/tests/apply_policy.rs
pub fn apply_policy_document_on_metadata(
    full_policy: &Map<String, Value>,
    metadata: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    // Here we have the full policy document and full metadata.
    // We need to check if it has any actual policy or not.

    let policy: Map<String, Value> = full_policy
        .get("metadata_policy")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    debug!("POLICY: {:?}", policy);

    // Next we should check for any forced metadata or not.
    let forced_meta: Map<String, Value> = full_policy
        .get("metadata")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    debug!("FORCED_METADATA: {:?}", forced_meta);

    // Result map that will hold all entity types
    let mut result: Map<String, Value> = Map::new();

    // Known entity types to process
    let entity_types = [
        "openid_relying_party",
        "openid_provider",
        "federation_entity",
        "oauth_client",
        "oauth_authorization_server",
        "oauth_resource",
    ];

    for entity_type in entity_types.iter() {
        // Check if metadata contains this entity type
        if metadata.contains_key(*entity_type) {
            // Apply forced metadata first
            let meta = apply_forced_metadata(entity_type, metadata, &forced_meta);

            // Check if policy contains this entity type
            if policy.contains_key(*entity_type) {
                let entity_policy = policy
                    .get(*entity_type)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone();
                // Apply policy on metadata
                let applied = apply_policy_on_metadata(entity_policy, &meta)?;
                result.insert(entity_type.to_string(), json!(applied));
            } else {
                // No policy for this entity type, just use metadata with forced values
                result.insert(entity_type.to_string(), json!(meta));
            }
        }
    }

    if result.is_empty() {
        // If we reach here, means there is no proper metadata for any known entity type.
        bail!("Could not apply policy to metadata.");
    }

    Ok(result)
}

/// Applies a metadata policy to metadata for a single entity type.
///
/// This is a wrapper around [`resolve_metadata_policy`] that handles the
/// resolution and returns the result as a `Map<String, Value>`.
///
/// # Arguments
///
/// * `policy` - The metadata policy containing operators for each metadata field
/// * `metadata` - The entity's metadata to apply the policy to
///
/// # Returns
///
/// Returns `Ok(Map<String, Value>)` with the resolved metadata, or `Err` if
/// policy constraints are violated.
///
/// # Errors
///
/// Returns an error if the metadata violates policy constraints.
///
/// # Example
///
/// ```rust
/// use serde_json::{json, Map, Value};
///
/// let policy: Map<String, Value> = json!({
///     "grant_types": {
///         "default": ["authorization_code"],
///         "subset_of": ["authorization_code", "implicit"]
///     }
/// }).as_object().unwrap().clone();
///
/// let metadata: Map<String, Value> = json!({
///     "application_type": "web"
/// }).as_object().unwrap().clone();
///
/// let result = oidfed_metadata_policy::apply_policy_on_metadata(policy, &metadata).unwrap();
///
/// // grant_types will have the default value ["authorization_code"]
/// ```
pub fn apply_policy_on_metadata(
    policy: Map<String, Value>,
    metadata: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    let result = resolve_metadata_policy(&policy, metadata);
    // If it is Okay, then we should put the resolved metadata to the val
    //
    match result {
        Ok(v) => {
            let temp: Map<String, Value> = v.as_object().unwrap().clone();
            Ok(temp)
        }
        Err(_) => {
            bail!("received error in applying metadata policy on metadata");
        }
    }
}
