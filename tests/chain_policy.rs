use oidfed_metadata_policy::{
    SubordinatePolicy, apply_policy_document_on_metadata, apply_policy_on_metadata, merge_policies,
    resolve_chain_metadata, resolve_metadata_policy,
};
use serde_json::{Map, Value, json};

fn statement(document: &Value) -> SubordinatePolicy<'_> {
    SubordinatePolicy {
        metadata_policy: document.get("metadata_policy"),
        metadata_policy_crit: document.get("metadata_policy_crit"),
        metadata: document.get("metadata"),
    }
}

#[test]
fn critical_declarations_are_checked_before_policy_is_combined() {
    let metadata = json!({"rp": {"name": "Campus"}});
    let optional = json!({"metadata_policy": {"rp":{"name":{"future_operator": true}}}});
    let declaration = json!({"metadata_policy_crit": ["future_operator"]});
    for statements in [
        [statement(&optional), statement(&declaration)],
        [statement(&declaration), statement(&optional)],
    ] {
        let error = resolve_chain_metadata(metadata.as_object().unwrap(), &statements).unwrap_err();
        assert!(error.to_string().contains("future_operator"));
    }
    assert_eq!(
        Value::Object(
            resolve_chain_metadata(metadata.as_object().unwrap(), &[statement(&optional)]).unwrap()
        ),
        metadata
    );
}

#[test]
fn invalid_critical_declarations_are_rejected_by_both_document_apis() {
    for critical in [
        Value::Null,
        json!("future"),
        json!([]),
        json!([42]),
        json!(["essential"]),
        json!(["future"]),
    ] {
        let doc = json!({"metadata_policy_crit": critical});
        assert!(resolve_chain_metadata(&Map::new(), &[statement(&doc)]).is_err());
        assert!(apply_policy_document_on_metadata(doc.as_object().unwrap(), &Map::new()).is_err());
    }
}

#[test]
fn malformed_single_and_merged_policies_fail_even_for_an_absent_role() {
    let metadata = json!({"other": {}});
    for bad in [
        json!(null),
        json!([]),
        json!({"rp":42}),
        json!({"rp":{"p":false}}),
        json!({"rp":{"p":{"essential":1}}}),
        json!({"rp":{"p":{"one_of":["a"],"subset_of":["a"]}}}),
    ] {
        let doc = json!({"metadata_policy":bad});
        assert!(merge_policies(&json!({}), &bad).is_err());
        assert!(merge_policies(&bad, &json!({})).is_err());
        assert!(resolve_chain_metadata(metadata.as_object().unwrap(), &[statement(&doc)]).is_err());
    }
    let high = json!({"rp":{"p":{"one_of":["a"]}}});
    let low = json!({"rp":{"p":{"add":["a"]}}});
    assert!(merge_policies(&high, &low).is_err());
}

#[test]
fn lower_superior_can_add_a_restriction_to_an_existing_role() {
    let high = json!({"metadata_policy":{"rp":{"alg":{"one_of":["RS256","ES256"]}}}, "metadata":{"rp":{"name":"ignored"}}});
    let low = json!({"metadata_policy":{"rp":{"alg":{"one_of":["ES256","PS256"]},"name":{"essential":true}}}});
    let leaf = json!({"rp":{"alg":"ES256"}});
    let resolve = |low: &Value| {
        resolve_chain_metadata(
            leaf.as_object().unwrap(),
            &[statement(&high), statement(low)],
        )
    };
    assert!(resolve(&low).is_err());
    let mut low = low;
    low["metadata"] = json!({"rp":{"name":"Campus"}});
    assert_eq!(
        resolve(&low).unwrap()["rp"],
        json!({"alg":"ES256","name":"Campus"})
    );
}

#[test]
fn incompatible_metadata_returns_an_error_and_optional_missing_values_stay_absent() {
    let metadata = json!({"rp":{"names":"Campus"}});
    let doc = json!({"metadata_policy":{"rp":{"names":{"add":["Central"]}}}});
    assert!(resolve_chain_metadata(metadata.as_object().unwrap(), &[statement(&doc)]).is_err());
    let doc = json!({"metadata_policy":{"rp":{"missing":{"essential":false},"names":{"essential":true}}}});
    assert_eq!(
        Value::Object(
            resolve_chain_metadata(metadata.as_object().unwrap(), &[statement(&doc)]).unwrap()
        ),
        metadata
    );
}

#[test]
fn operator_inputs_and_results_have_supported_json_types() {
    for (value, policy) in [
        (json!(null), json!({"essential":false})),
        (json!(["ok", true]), json!({"subset_of":["ok"]})),
        (json!([true]), json!({"superset_of":[]})),
        (json!([1, "ok"]), json!({"add":[]})),
        (json!([1]), json!({"add":["ok"]})),
        (json!(["ok"]), json!({"add":["ok",1]})),
    ] {
        let leaf = json!({"rp":{"field":value}});
        let doc = json!({"metadata_policy":{"rp":{"field":policy}}});
        assert!(resolve_chain_metadata(leaf.as_object().unwrap(), &[statement(&doc)]).is_err());
    }
}

#[test]
fn standalone_empty_one_of_allows_only_an_absent_parameter() {
    let rule = json!({"metadata_policy": {"rp": {"alg": {"one_of": []}}}});
    let optional_absent = json!({"rp": {}});
    let absent = optional_absent.as_object().unwrap();
    assert_eq!(
        resolve_chain_metadata(absent, &[statement(&rule)]).unwrap(),
        *absent
    );

    let present = json!({"rp": {"alg": "ES256"}});
    assert!(resolve_chain_metadata(present.as_object().unwrap(), &[statement(&rule)]).is_err());

    // Two one_of operators with no common value invalidate the chain during
    // the merge, even when the leaf omits the optional parameter (§6.1.3.1.4).
    let other = json!({"metadata_policy": {"rp": {"alg": {"one_of": ["ES256"]}}}});
    assert!(resolve_chain_metadata(absent, &[statement(&rule), statement(&other)]).is_err());
}

#[test]
fn empty_resolved_client_scope_is_an_error_even_when_optional() {
    let present = json!({"oauth_client": {"scope": "openid"}});
    let absent = json!({"oauth_client": {}});
    for essential in [false, true] {
        let doc = json!({"metadata_policy": {"oauth_client": {
            "scope": {"subset_of": ["email"], "essential": essential}
        }}});
        let resolve =
            |leaf: &Value| resolve_chain_metadata(leaf.as_object().unwrap(), &[statement(&doc)]);
        assert!(resolve(&present).is_err());
        if essential {
            assert!(resolve(&absent).is_err());
        } else {
            assert_eq!(resolve(&absent).unwrap(), *absent.as_object().unwrap());
        }
    }
}

#[test]
fn generic_helpers_require_an_array_for_scope_subset_of() {
    let policy = json!({"scope": {"subset_of": ["email"]}});
    let policy = policy.as_object().unwrap();
    let metadata = json!({"scope": "openid email"});
    let metadata = metadata.as_object().unwrap();

    assert!(resolve_metadata_policy(policy, metadata).is_err());
    assert!(apply_policy_on_metadata(policy.clone(), metadata).is_err());
}

#[test]
fn oauth_scope_tokens_round_trip_only_on_client_roles() {
    for role in ["openid_relying_party", "oauth_client"] {
        let leaf = json!({role:{"scope":"openid email"}});
        let doc = json!({"metadata_policy":{role:{"scope":{"subset_of":["email"]}}}});
        let result = resolve_chain_metadata(leaf.as_object().unwrap(), &[statement(&doc)]).unwrap();
        assert_eq!(result[role]["scope"], "email");
        let bad = json!({"metadata_policy":{role:{"scope":{"add":["two tokens"]}}}});
        assert!(resolve_chain_metadata(leaf.as_object().unwrap(), &[statement(&bad)]).is_err());
    }
    let leaf = json!({"custom":{"scope":["group"]}});
    let doc = json!({"metadata_policy":{"custom":{"scope":{"essential":true}}}});
    assert_eq!(
        resolve_chain_metadata(leaf.as_object().unwrap(), &[statement(&doc)]).unwrap()["custom"]["scope"],
        json!(["group"])
    );
}

#[test]
fn signed_policy_requires_at_least_one_member_at_each_level() {
    for policy in [json!({}), json!({"rp":{}}), json!({"rp":{"name":{}}})] {
        let doc = json!({"metadata_policy":policy});
        assert!(resolve_chain_metadata(&Map::new(), &[statement(&doc)]).is_err());
        assert!(apply_policy_document_on_metadata(doc.as_object().unwrap(), &Map::new()).is_err());
    }
    assert!(resolve_chain_metadata(&Map::new(), &[statement(&json!({}))]).is_ok());
}

#[test]
fn metadata_errors_are_detected_before_overrides_or_policy() {
    let leaf = json!({"rp": {"name": null}});
    let overrides = json!({"metadata":{"rp":{"name":"Campus"}}});
    let removal = json!({"metadata_policy":{"rp":{"name":{"value":null}}}});
    let leaf = leaf.as_object().unwrap();
    assert!(resolve_chain_metadata(leaf, &[]).is_err());
    assert!(resolve_chain_metadata(leaf, &[statement(&overrides)]).is_err());
    assert!(apply_policy_document_on_metadata(removal.as_object().unwrap(), leaf).is_err());
    let fields = leaf["rp"].as_object().unwrap();
    assert!(resolve_metadata_policy(&Map::new(), fields).is_err());
    assert!(apply_policy_on_metadata(Map::new(), fields).is_err());

    let valid = json!({"rp": {}});
    for claim in [
        json!(null),
        json!({"rp":{"name":null}}),
        json!({"unused":false}),
        json!({"unused":{"name":null}}),
    ] {
        let doc = json!({"metadata":claim});
        let leaf = valid.as_object().unwrap();
        assert!(resolve_chain_metadata(leaf, &[statement(&doc)]).is_err());
        assert!(resolve_chain_metadata(leaf, &[statement(&doc), statement(&overrides)]).is_err());
    }
}

#[test]
fn nested_nulls_empty_roles_and_explicit_parameter_removal_are_valid() {
    let leaf = json!({"rp":{"name":"Campus","settings":{"fallback":null}},"custom":{}});
    let doc = json!({"metadata_policy":{"rp":{"name":{"value":null}}},
                     "metadata":{"rp":{"list":[null]},"unused":{}}});
    let result =
        apply_policy_document_on_metadata(doc.as_object().unwrap(), leaf.as_object().unwrap())
            .unwrap();
    assert_eq!(
        Value::Object(result),
        json!({"rp":{"settings":{"fallback":null},"list":[null]},"custom":{}})
    );
}

#[test]
fn merged_policy_can_be_reissued_after_ignoring_optional_extensions() {
    let optional = json!({"rp":{"custom":{"extension":true},"name":{"extension":"future"}},"unused":{"p":{"extension":1}}});
    assert!(merge_policies(&optional, &optional).unwrap().is_empty());
    let known = json!({"rp":{"name":{"value":"Campus","another_extension":1}}});
    for (higher, lower) in [(&optional, &known), (&known, &optional)] {
        let merged = merge_policies(higher, lower).unwrap();
        let doc = json!({"metadata_policy":merged});
        assert_eq!(
            doc["metadata_policy"],
            json!({"rp":{"name":{"value":"Campus"}}})
        );
        let leaf = json!({"rp":{}});
        let resolved =
            resolve_chain_metadata(leaf.as_object().unwrap(), &[statement(&doc)]).unwrap();
        assert_eq!(resolved["rp"]["name"], "Campus");
    }
}
