## Under heavy development

DO NOT USE IN PRODUCTION.

This is an implementation of `metadata policy` resolve & applymethods for [OpenID Federation 1.0 draft 42](https://openid.net/specs/openid-federation-1_0.html). 

## LICENSE

BSD-2-Clause

## Test data I am using

[2025-02-13](https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/downloads/metadata-policy-test-vectors-2025-02-13.json) based on https://connect2id.com/blog/metadata-policy-test-vectors-openid-federation

Put the file in the `./data/` directory (create it if required).


## Major exported function(s)

`resolve_metadata_policy` & `merge_policies`.
