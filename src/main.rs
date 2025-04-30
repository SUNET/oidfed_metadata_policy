#![allow(unused)]
use oidfed_metadata_policy::*;
use serde_json::Value;
use std::collections::HashSet;
use std::io;

fn main() {
    let mut stdin = io::stdin();
    env_logger::init();
    let data = std::fs::read("data/metadata-policy-test-vectors-2025-02-13.json").unwrap();
    let data_str = std::str::from_utf8(&data).unwrap();
    let input: Value = serde_json::from_str(data_str).unwrap();

    for one_test in input.as_array().unwrap().iter() {
        let input_map = one_test.as_object().unwrap();
        let n = &input_map["n"];
        // For one test
        //if n.as_i64().unwrap() != 1458 {
        //continue;
        //}
        eprintln!("Running {}", n);
        let merged = merge_policies(&input_map["TA"], &input_map["INT"]);
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
                        } else {
                            // Merge worked, now we should apply the input to the merged answer
                            let metadata = input_map.get("metadata").unwrap().as_object().unwrap();
                            let result = resolve_metadata_policy(&m, metadata);
                            if result.is_err() {
                                let expected = input_map.get("error");
                                match expected {
                                    Some(exp) => {
                                        eprintln!("Received error in policy as expected\n");
                                        continue;
                                    }
                                    None => panic!("Missing error output at {}", n),
                                }
                                panic!("{}", result.err().unwrap());
                            }
                            let result = result.ok().unwrap();
                            let resolved = input_map.get("resolved").unwrap();
                            eprintln!(
                                "Result: {:?}  and expected_result: {:?}\n\n",
                                result, resolved
                            );
                            if !check_equal(resolved, &result) {
                                panic!("Failed");
                            }

                            // Read a single byte and discard
                            //let _ = stdin.read(&mut [0u8]).unwrap();
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
    }
}
