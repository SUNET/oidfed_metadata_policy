use anyhow::Result;
use env_logger;
use serde_json::{Value, json};

fn check_equal_values(v1: Value, v2: Value) -> Result<()> {
    if oidfed_metadata_policy::check_equal(&v1, &v2) {
        Ok(())
    } else {
        let message = format!("Values are not equal, got {v1:?} expected {v2:?}");
        return Err(anyhow::anyhow!(message));
    }
}

#[test]
fn test_apply_blank_policy() {
    env_logger::init();
    let metadata = json!( {
        "federation_entity": {
            "logo_uri": "https://fakeop0.labb.sunet.se/fake.png",
            "organization_name": "Fake Organization"
        },
        "openid_relying_party": {
            "application_type": "web",
            "redirect_uris": ["https://openid.sunet.se/rp/callback"],
            "organization_name": "SUNET",
            "logo_uri": "https://www.sunet.se/sunet/images/32x32.png",
            "grant_types": ["authorization_code", "implicit"],
            "signed_jwks_uri": "https://openid.sunet.se/rp/signed_jwks.jose",
            "jwks_uri": "https://openid.sunet.se/rp/jwks.json",
            "client_registration_types": ["automatic"]
        }
    });
    let metadata_obj = metadata.as_object().unwrap();

    let full_policy = json!( {"metadata_policy": {}, "metadata": {
        "openid_relying_party": {
            "application_type": "mutant",
            "system": ["py", "rust"]
        },
        "extra_field": "extra_value"
    }});

    let fp = full_policy.as_object().unwrap();

    let applied_metadata =
        oidfed_metadata_policy::apply_policy_document_on_metadata(fp, metadata_obj)
            .expect("Applying metadata policy should succeed");

    let expected_metadata = json!({
        "federation_entity": {
            "logo_uri": "https://fakeop0.labb.sunet.se/fake.png",
            "organization_name": "Fake Organization"
        },
        "openid_relying_party": {
            "application_type": "mutant",
            "client_registration_types": ["automatic"],
            "grant_types": ["authorization_code", "implicit"],
            "jwks_uri": "https://openid.sunet.se/rp/jwks.json",
            "logo_uri": "https://www.sunet.se/sunet/images/32x32.png",
            "organization_name": "SUNET",
            "redirect_uris": ["https://openid.sunet.se/rp/callback"],
            "signed_jwks_uri": "https://openid.sunet.se/rp/signed_jwks.jose",
            "system": ["py", "rust"]
        }
    });

    assert_eq!(json!(applied_metadata), expected_metadata);
}

#[test]
fn test_apply_policy_superset_failure() {
    let metadata = json!( {
        "federation_entity": {
            "logo_uri": "https://fakeop0.labb.sunet.se/fake.png",
            "organization_name": "Fake Organization"
        },
        "openid_relying_party": {
            "application_type": "web",
            "redirect_uris": ["https://openid.sunet.se/rp/callback"],
            "organization_name": "SUNET",
            "logo_uri": "https://www.sunet.se/sunet/images/32x32.png",
            "grant_types": ["authorization_code", "implicit"],
            "signed_jwks_uri": "https://openid.sunet.se/rp/signed_jwks.jose",
            "jwks_uri": "https://openid.sunet.se/rp/jwks.json",
            "client_registration_types": ["automatic"]
        }
    });
    let metadata_obj = metadata.as_object().unwrap();

    let full_policy = json!( {
    "metadata_policy": {
        "openid_relying_party": {
            "grant_types": {
                "superset_of":["authorization_code", "implicit", "client"]
            },
        }
    },
    "metadata": {
        "openid_relying_party": {
            "application_type": "mutant",
            "system": ["py", "rust"]
        },
        "extra_field": "extra_value"
    }});

    let fp = full_policy.as_object().unwrap();

    let applied_metadata =
        oidfed_metadata_policy::apply_policy_document_on_metadata(fp, metadata_obj);

    assert!(
        applied_metadata.is_err(),
        "Expected error because grant_types is not a superset of required values"
    );
}

#[test]
fn test_apply_policy_subset_of_without_metadata() {
    let metadata = json!( {
        "federation_entity": {
            "logo_uri": "https://fakeop0.labb.sunet.se/fake.png",
            "organization_name": "Fake Organization"
        },
        "openid_relying_party": {
            "application_type": "web",
            "redirect_uris": ["https://openid.sunet.se/rp/callback"],
            "organization_name": "SUNET",
            "logo_uri": "https://www.sunet.se/sunet/images/32x32.png",
            "grant_types": ["authorization_code", "implicit"],
            "signed_jwks_uri": "https://openid.sunet.se/rp/signed_jwks.jose",
            "jwks_uri": "https://openid.sunet.se/rp/jwks.json",
            "client_registration_types": ["automatic"]
        }
    });
    let metadata_obj = metadata.as_object().unwrap();

    let full_policy = json!( {
    "metadata_policy": {
        "openid_relying_party": {
            "grant_types": {
                "subset_of":["authorization_code", "implicit", "client"]
            },
        }
    },
    "metadata": {}});

    let fp = full_policy.as_object().unwrap();

    let applied_metadata =
        oidfed_metadata_policy::apply_policy_document_on_metadata(fp, metadata_obj)
            .expect("Policy should be applied.");

    let expected_metadata = json!({
        "federation_entity": {
            "logo_uri": "https://fakeop0.labb.sunet.se/fake.png",
            "organization_name": "Fake Organization"
        },
        "openid_relying_party": {
            "application_type": "mutant",
            "client_registration_types": ["automatic"],
            "grant_types": ["authorization_code", "implicit"],
            "jwks_uri": "https://openid.sunet.se/rp/jwks.json",
            "logo_uri": "https://www.sunet.se/sunet/images/32x32.png",
            "organization_name": "SUNET",
            "redirect_uris": ["https://openid.sunet.se/rp/callback"],
            "signed_jwks_uri": "https://openid.sunet.se/rp/signed_jwks.jose",
            "system": ["py", "rust"]
        }
    });

    _ = check_equal_values(json!(applied_metadata), expected_metadata);
}

#[test]
fn test_apply_policy_subset_of_with_metadata() {
    let metadata = json!( {
        "federation_entity": {
            "logo_uri": "https://fakeop0.labb.sunet.se/fake.png",
            "organization_name": "Fake Organization"
        },
        "openid_relying_party": {
            "application_type": "web",
            "redirect_uris": ["https://openid.sunet.se/rp/callback"],
            "organization_name": "SUNET",
            "logo_uri": "https://www.sunet.se/sunet/images/32x32.png",
            "grant_types": ["authorization_code", "implicit"],
            "signed_jwks_uri": "https://openid.sunet.se/rp/signed_jwks.jose",
            "jwks_uri": "https://openid.sunet.se/rp/jwks.json",
            "client_registration_types": ["automatic"]
        }
    });
    let metadata_obj = metadata.as_object().unwrap();

    let full_policy = json!( {
    "metadata_policy": {
        "openid_relying_party": {
            "grant_types": {
                "subset_of":["authorization_code", "implicit", "client"]
            },
        }
    },
    "metadata": {
        "openid_relying_party": {
            "application_type": "mutant",
            "system": ["py", "rust"]
        },
        "extra_field": "extra_value"
    }});

    let fp = full_policy.as_object().unwrap();

    let applied_metadata =
        oidfed_metadata_policy::apply_policy_document_on_metadata(fp, metadata_obj)
            .expect("Applying metadata policy should succeed");
    let expected_metadata = json!({
        "federation_entity": {
            "logo_uri": "https://fakeop0.labb.sunet.se/fake.png",
            "organization_name": "Fake Organization"
        },
        "openid_relying_party": {
            "application_type": "mutant",
            "client_registration_types": ["automatic"],
            "grant_types": ["authorization_code", "implicit"],
            "jwks_uri": "https://openid.sunet.se/rp/jwks.json",
            "logo_uri": "https://www.sunet.se/sunet/images/32x32.png",
            "organization_name": "SUNET",
            "redirect_uris": ["https://openid.sunet.se/rp/callback"],
            "signed_jwks_uri": "https://openid.sunet.se/rp/signed_jwks.jose",
            "system": ["py", "rust"]
        }
    });

    _ = check_equal_values(json!(applied_metadata), expected_metadata);
}
