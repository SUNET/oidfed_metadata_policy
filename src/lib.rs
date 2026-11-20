//! # OpenID Federation Metadata Policy
//!
//! This crate implements metadata policy operations for OpenID Federation as specified in
//! [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html).
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

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Map, Value, json};

use std::collections::HashSet;

/// Merges a Trust Anchor's (TA) policy on top of an Intermediate Authority's (IA) policy
/// according to the OpenID Federation policy merging rules.
///
/// This function implements the policy merge algorithm defined in
/// [Section 6.1.3](https://openid.net/specs/openid-federation-1_1.html#section-6.1.3)
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
/// the policies cannot be merged due to conflicts. Parameters and roles with
/// no supported operators are omitted. If the map is empty, omit the
/// `metadata_policy` claim when issuing a statement (§6.1.2).
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
    let mut merged = Map::new();
    for policy in [ta_policies_in, ia_policies_in] {
        for (role, fields) in object(policy, "metadata_policy")? {
            let empty = json!({});
            let previous = merged.get(role).unwrap_or(&empty);
            let fields = merge_one_type_policy(previous, fields)
                .with_context(|| format!("invalid policy for {role}"))?;
            if !fields.is_empty() {
                merged.insert(role.clone(), Value::Object(fields));
            }
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
/// [Section 6.1.3.1](https://openid.net/specs/openid-federation-1_1.html#section-6.1.3.1)
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
    let mut merged = Map::new();
    for policy in [ta_policies_in, ia_policies_in] {
        for (field, operators) in object(policy, "entity type policy")? {
            let rules = object(operators, "parameter policy")?;
            validate_operators(rules).with_context(|| format!("invalid policy for {field}"))?;
            // Ignoring optional extensions must not create an empty parameter
            // policy. Each emitted parameter needs at least one operator (§6.1.2).
            if !rules.keys().any(|name| standard_operator(name)) {
                continue;
            }
            let existing = merged.entry(field.clone()).or_insert_with(|| json!({}));
            let result = existing
                .as_object_mut()
                .expect("initialized as a parameter policy");
            for (name, operand) in rules.iter().filter(|(name, _)| standard_operator(name)) {
                let value = match result.get(name) {
                    Some(old) => merge_operand(name, old, operand)?,
                    None => operand.clone(),
                };
                result.insert(name.clone(), value);
            }
            validate_operators(result)
                .with_context(|| format!("incompatible policies for {field}"))?;
        }
    }
    Ok(merged)
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow!("{what} must be an object"))
}

fn array<'a>(value: &'a Value, what: &str) -> Result<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("{what} must be an array"))
}

// Set operators accept homogeneous arrays (§6.1.3.1). Check both input
// operands and unions, which can otherwise mix two valid element types.
fn set_elements<'a>(value: &'a Value, what: &str) -> Result<&'a [Value]> {
    let items = array(value, what)?;
    ensure!(
        items.iter().all(Value::is_string)
            || items.iter().all(Value::is_number)
            || items.iter().all(Value::is_object),
        "{what} expects an array of strings, numbers or objects"
    );
    Ok(items)
}

fn standard_operator(name: &str) -> bool {
    matches!(
        name,
        "value" | "add" | "default" | "one_of" | "subset_of" | "superset_of" | "essential"
    )
}

/// Section 3.1.3 reserves this nonempty list for additional operators.
/// This release implements the seven standard operators and no extensions.
pub fn validate_metadata_policy_crit(value: &Value) -> Result<()> {
    let names = array(value, "metadata_policy_crit")?;
    ensure!(!names.is_empty(), "metadata_policy_crit must be nonempty");
    for item in names {
        let name = item
            .as_str()
            .filter(|s| !s.is_empty())
            .context("invalid critical operator name")?;
        ensure!(
            !standard_operator(name),
            "standard operator {name} cannot be declared critical"
        );
    }
    bail!(
        "unsupported critical metadata policy operator: {}",
        names[0]
    )
}

fn validate_operators(rules: &Map<String, Value>) -> Result<()> {
    for (name, operand) in rules {
        match name.as_str() {
            "add" | "one_of" | "subset_of" | "superset_of" => {
                set_elements(operand, name)?;
            }
            "essential" => ensure!(operand.is_boolean(), "essential must be boolean"),
            "default" => ensure!(!operand.is_null(), "default cannot be null"),
            _ => {}
        }
    }
    if let Some(choices) = rules.get("one_of") {
        ensure!(
            ["add", "subset_of", "superset_of"]
                .iter()
                .all(|k| !rules.contains_key(*k)),
            "one_of cannot be combined with array operators"
        );
        if let Some(value) = rules.get("value") {
            ensure!(
                array(choices, "one_of")?.contains(value),
                "value is outside one_of"
            );
        }
    }
    if rules.get("value").is_some_and(Value::is_null) {
        ensure!(
            !rules.contains_key("default") && rules.get("essential") != Some(&Value::Bool(true)),
            "value null conflicts with default or essential true"
        );
    }
    for (subset, superset) in [
        ("add", "value"),
        ("value", "subset_of"),
        ("superset_of", "value"),
        ("add", "subset_of"),
        ("superset_of", "subset_of"),
    ] {
        if let (Some(lhs), Some(rhs)) = (rules.get(subset), rules.get(superset)) {
            ensure!(
                lhs.is_array() && rhs.is_array() && is_subset_of(lhs, rhs),
                "{subset} must be a subset of {superset}"
            );
        }
    }
    Ok(())
}

// Preserve the superior's ordering where possible. Set operations deduplicate
// by JSON value, including when one operand already contains repetitions.
fn combine_arrays(left: &[Value], right: &[Value], intersection: bool) -> Vec<Value> {
    let in_right: HashSet<_> = right.iter().collect();
    let mut seen = HashSet::new();
    let additional = if intersection { &[][..] } else { right };
    left.iter()
        .chain(additional)
        .filter(|item| (!intersection || in_right.contains(*item)) && seen.insert(*item))
        .cloned()
        .collect()
}

fn merge_operand(name: &str, old: &Value, new: &Value) -> Result<Value> {
    match name {
        "essential" => Ok(Value::Bool(
            old == &Value::Bool(true) || new == &Value::Bool(true),
        )),
        "add" | "superset_of" | "subset_of" | "one_of" => {
            let common = matches!(name, "one_of" | "subset_of");
            let result = combine_arrays(array(old, name)?, array(new, name)?, common);
            ensure!(
                name != "one_of" || !result.is_empty(),
                "one_of intersection is empty"
            );
            Ok(Value::Array(result))
        }
        _ if old == new => Ok(old.clone()),
        _ => bail!("conflicting {name} operands"),
    }
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
/// This helper receives no entity role and processes `scope` as its supplied
/// JSON type. Applying `subset_of` to the string `"openid email"` returns an
/// error because the operator expects an array. For OAuth client scope tokens,
/// use [`apply_policy_document_on_metadata`] for one verified statement or
/// [`resolve_chain_metadata`] for a verified chain. Both use the entity role
/// to split the scope string before applying policy and join the tokens afterwards.
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
/// - An essential field is missing
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
    validate_metadata_parameters(metadata)?;
    resolve_role_metadata(policy, metadata, false)
}

// Section 5 prohibits null at the parameter boundary. Objects and arrays
// inside a parameter follow the schema of that parameter's entity type.
fn validate_metadata_parameters(parameters: &Map<String, Value>) -> Result<()> {
    if let Some((name, _)) = parameters.iter().find(|(_, value)| value.is_null()) {
        bail!("metadata parameter {name} cannot be null");
    }
    Ok(())
}

fn validate_metadata(metadata: &Map<String, Value>) -> Result<()> {
    for (role, values) in metadata {
        let parameters = values
            .as_object()
            .ok_or_else(|| anyhow!("metadata for {role} must be an object"))?;
        validate_metadata_parameters(parameters)
            .with_context(|| format!("invalid metadata for {role}"))?;
    }
    Ok(())
}

// RFC 6749 scope-token excludes spaces, quotes, backslashes and controls.
fn scope_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn resolve_role_metadata(
    policy: &Map<String, Value>,
    metadata: &Map<String, Value>,
    oauth_client: bool,
) -> Result<Value> {
    let mut result = metadata.clone();
    for (name, operators) in policy {
        let rules = object(operators, "parameter policy")?;
        validate_operators(rules)?;
        if !rules.keys().any(|op| standard_operator(op)) {
            continue;
        }
        let mut current = result.remove(name);
        // OAuth client scope is an array of scope tokens during policy
        // processing and a space-delimited string on the wire (§6.1.3.1.8).
        let scope = oauth_client && name == "scope";
        if scope && let Some(wire) = &current {
            let text = wire.as_str().context("client scope must be a string")?;
            let tokens: Vec<_> = text.split(' ').collect();
            ensure!(
                tokens.iter().all(|s| scope_token(s)),
                "invalid client scope"
            );
            current = Some(json!(tokens));
        }
        if let Some(value) = rules.get("value") {
            current = (!value.is_null()).then(|| value.clone());
        }
        if let Some(add) = rules.get("add") {
            let prior = current
                .as_ref()
                .map(|v| set_elements(v, name))
                .transpose()?
                .unwrap_or_default();
            let combined = Value::Array(combine_arrays(prior, array(add, "add")?, false));
            set_elements(&combined, name)?;
            current = Some(combined);
        }
        if current.is_none() {
            current = rules.get("default").cloned();
        }
        if let Some(value) = &mut current {
            ensure!(!value.is_null(), "{name} cannot resolve to null");
            if let Some(choices) = rules.get("one_of") {
                ensure!(
                    array(choices, "one_of")?.contains(value),
                    "{name} is outside one_of"
                );
            }
            if let Some(subset) = rules.get("subset_of") {
                *value = Value::Array(combine_arrays(
                    set_elements(value, name)?,
                    array(subset, "subset_of")?,
                    true,
                ));
            }
            if let Some(required) = rules.get("superset_of") {
                set_elements(value, name)?;
                ensure!(
                    is_subset_of(required, value),
                    "{name} omits a required value"
                );
            }
            if scope {
                let tokens = array(value, "scope")?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .filter(|s| scope_token(s))
                            .context("invalid scope token")
                    })
                    .collect::<Result<Vec<_>>>()?;
                // RFC 6749 §3.3 requires at least one token. Dropping a present
                // scope here could grant registration defaults (RFC 7591 §2).
                ensure!(!tokens.is_empty(), "client scope resolved to zero tokens");
                *value = Value::String(tokens.join(" "));
            }
        }
        ensure!(
            rules.get("essential") != Some(&Value::Bool(true))
                || current.as_ref().is_some_and(|v| !v.is_null()),
            "missing essential parameter {name}"
        );
        if let Some(value) = current {
            result.insert(name.clone(), value);
        }
    }
    Ok(Value::Object(result))
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
///   - `metadata_policy`: Policy operators for each entity type (omit when there is no policy)
///   - `metadata_policy_crit`: Critical extension names (optional)
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
/// - A policy claim, critical declaration, or role metadata object is malformed
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
/// - `test_apply_without_policy` - Applying forced metadata with no policy claim
/// - `test_apply_policy_superset_failure` - Error handling when `superset_of` constraint fails
/// - `test_apply_policy_subset_of_without_metadata` - Using `subset_of` without forced metadata
/// - `test_apply_policy_subset_of_with_metadata` - Combining `subset_of` with forced metadata
///
/// [`tests/apply_policy.rs`]: https://github.com/SUNET/oidfed_metadata_policy/blob/main/tests/apply_policy.rs
pub fn apply_policy_document_on_metadata(
    full_policy: &Map<String, Value>,
    metadata: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    resolve_chain_metadata(
        metadata,
        &[SubordinatePolicy {
            metadata_policy: full_policy.get("metadata_policy"),
            metadata_policy_crit: full_policy.get("metadata_policy_crit"),
            metadata: full_policy.get("metadata"),
        }],
    )
}

fn apply_resolved_policy(
    policy: &Map<String, Value>,
    forced: Option<&Value>,
    metadata: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    let forced = forced.map(|v| object(v, "superior metadata")).transpose()?;
    let mut result = Map::new();
    for (role, values) in metadata {
        let mut values = object(values, "entity metadata")?.clone();
        // The immediate superior may override parameters only in a role the
        // leaf actually declares. Other superiors' metadata is irrelevant.
        if let Some(overrides) = forced.and_then(|m| m.get(role)) {
            values.extend(object(overrides, "superior role metadata")?.clone());
        }
        let resolved = match policy.get(role) {
            Some(fields) => resolve_role_metadata(
                object(fields, "role policy")?,
                &values,
                matches!(role.as_str(), "oauth_client" | "openid_relying_party"),
            )?,
            None => Value::Object(values),
        };
        result.insert(role.clone(), resolved);
    }
    Ok(result)
}

/// Signed claim values from one subordinate statement. Absence is distinct
/// from a JSON null or a malformed claim.
pub struct SubordinatePolicy<'a> {
    pub metadata_policy: Option<&'a Value>,
    pub metadata_policy_crit: Option<&'a Value>,
    pub metadata: Option<&'a Value>,
}

/// Resolve leaf metadata from statements supplied in anchor-to-leaf order.
/// Critical extensions must be understood across the entire candidate chain
/// before any merge can discard an unknown operator (§6.1.4.1).
///
/// ```
/// use oidfed_metadata_policy::{SubordinatePolicy, resolve_chain_metadata};
/// use serde_json::json;
///
/// let leaf = json!({"openid_relying_party": {"application_type": "web"}});
/// let signed_claims = json!({"metadata_policy": {
///     "openid_relying_party": {"application_type": {"one_of": ["web"]}}
/// }});
/// let statement = SubordinatePolicy {
///     metadata_policy: signed_claims.get("metadata_policy"),
///     metadata_policy_crit: signed_claims.get("metadata_policy_crit"),
///     metadata: signed_claims.get("metadata"),
/// };
/// let resolved = resolve_chain_metadata(leaf.as_object().unwrap(), &[statement])?;
/// assert_eq!(resolved["openid_relying_party"]["application_type"], "web");
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn resolve_chain_metadata(
    metadata: &Map<String, Value>,
    statements: &[SubordinatePolicy<'_>],
) -> Result<Map<String, Value>> {
    validate_metadata(metadata).context("invalid leaf metadata")?;
    for statement in statements {
        if let Some(critical) = statement.metadata_policy_crit {
            validate_metadata_policy_crit(critical)?;
        }
        // Validate every claim before selecting overrides. A higher superior's
        // metadata can be inapplicable to this leaf and still be malformed.
        if let Some(claim) = statement.metadata {
            validate_metadata(object(claim, "superior metadata")?)
                .context("invalid superior metadata")?;
        }
    }
    let mut merged = Map::new();
    for statement in statements {
        if let Some(policy) = statement.metadata_policy {
            let roles = object(policy, "metadata_policy")?;
            ensure!(
                !roles.is_empty(),
                "metadata_policy must contain an entity type"
            );
            for fields in roles.values() {
                let fields = object(fields, "entity type policy")?;
                ensure!(
                    !fields.is_empty(),
                    "entity type policy must contain a parameter"
                );
                for rules in fields.values() {
                    ensure!(
                        !object(rules, "parameter policy")?.is_empty(),
                        "parameter policy must contain an operator"
                    );
                }
            }
            merged = merge_policies(&Value::Object(merged), policy)?;
        }
    }
    apply_resolved_policy(
        &merged,
        statements.last().and_then(|s| s.metadata),
        metadata,
    )
}

/// Applies a metadata policy to metadata for a single entity type.
///
/// This is a wrapper around [`resolve_metadata_policy`] that handles the
/// resolution and returns the result as a `Map<String, Value>`.
///
/// Like [`resolve_metadata_policy`], this helper treats a string-valued
/// `scope` as a single string. For OAuth client scope processing, use
/// [`apply_policy_document_on_metadata`] or [`resolve_chain_metadata`].
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
    match resolve_metadata_policy(&policy, metadata)? {
        Value::Object(resolved) => Ok(resolved),
        _ => unreachable!("resolved metadata is an object"),
    }
}
