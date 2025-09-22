use core::error::Error;
use env_logger;
use std::{fs::File, io::BufReader};

use serde_json::{Map, Value};

const TEST_FILE: &str = "data/metadata-policy-test-vectors-2025-02-13.json";
const TEST_DATA_SOURCE: &str =
    "https://connect2id.com/blog/metadata-policy-test-vectors-openid-federation";

#[test]
fn test_policy_constraints() {
    env_logger::init();
    let file = File::open(TEST_FILE).expect(&format!(
        "Please download test data from {TEST_DATA_SOURCE} and save it as {TEST_FILE}"
    ));
    let input: Vec<Map<String, Value>> =
        serde_json::from_reader(BufReader::new(file)).expect("Test data must be valid JSON");
    let failed: Vec<_> = input
        .into_iter()
        .filter_map(|case| check_test_case(case).err())
        .collect();
    assert!(
        failed.is_empty(),
        "The following test cases didn't succeed: {failed:#?}"
    );
}

fn check_test_case(case: Map<String, Value>) -> Result<(), Box<dyn Error>> {
    let Some(merged) = merge_test_case_policies(&case)? else {
        // correctly resulted in error, nothing else to check
        return Ok(());
    };
    let n = case["n"]
        .as_i64()
        .expect("Test case should have numeric index n");
    let metadata = case["metadata"]
        .as_object()
        .expect("Metadata in test case should be an object");
    match oidfed_metadata_policy::resolve_metadata_policy(&merged, metadata) {
        Err(err) => match case.get("error") {
            Some(expected) if expected == "invalid_metadata" => {
                eprintln!("Case {n}: expected resolution error, received error {err}");
                Ok(())
            }
            _ => {
                let message = format!("Case {n}: resolution errored with {err}, expected success");
                Err(message)?
            }
        },
        Ok(resolved) => {
            let Some(expected) = case.get("resolved") else {
                let message = format!("Case {n}: unexpected successful resolution");
                Err(message)?
            };
            if oidfed_metadata_policy::check_equal(&resolved, expected) {
                Ok(())
            } else {
                let message = format!(
                    "Case {n}: resolved policy differs from expected, got {resolved:?} expected {expected:?}"
                );
                Err(message)?
            }
        }
    }
}

///  Try merging the Trust Anchor's and Intermediate Entity's metadata policies.
///  Returns Err if the result doesn't match what's expected, Ok(None) if
///  the test case expected an error (and we did produce one), and Ok(Some(merged_policy))
///  if the policies were successfully merged producing the expected value
fn merge_test_case_policies(
    case: &Map<String, Value>,
) -> Result<Option<Map<String, Value>>, Box<dyn Error>> {
    let n = case["n"]
        .as_i64()
        .expect("Test case should have numeric index n");
    let ta = &case["TA"];
    let int = &case["INT"];
    match oidfed_metadata_policy::merge_one_type_policy(ta, int) {
        Err(err) => match case.get("error") {
            Some(expected) if expected == "invalid_policy" => {
                eprintln!("Case {n}: expected merge error, received error {err}");
                Ok(None)
            }
            _ => {
                let message = format!("Case {n}: merge errored with {err}, expected success");
                Err(message)?
            }
        },
        Ok(merged) => {
            let Some(expected) = case.get("merged") else {
                let message = format!("Case {n}: unexpected successful merge");
                Err(message)?
            };
            let expected = expected
                .as_object()
                .expect("Merge in test case should be an object");
            if &merged != expected {
                let message = format!(
                    "Case {n}: merged policies differ from expected, got {merged:?} expected {expected:?}"
                );
                Err(message)?
            }
            Ok(Some(merged))
        }
    }
}
