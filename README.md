This Rust library merges and applies metadata policies for
[OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html)

## LICENSE

BSD-2-Clause

## To run the tests

```
cargo test
```

## Test data I am using

[2025-02-13](https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/downloads/metadata-policy-test-vectors-2025-02-13.json) based on https://connect2id.com/blog/metadata-policy-test-vectors-openid-federation

The repository includes the vectors in `data/`. To run the full test suite
from a crates.io source archive, download the linked file into `data/` first.


## Major exported function(s)

- `merge_policies`
- `apply_policy_document_on_metadata`
- `resolve_chain_metadata`

## Resolving a verified trust chain in 0.9.0

Pass the leaf's entity metadata and a slice of `SubordinatePolicy` values
in order from the trust anchor's statement down to the statement about
the leaf. Supply all three claims from each subordinate statement. Use
`None` for an absent claim and preserve a present JSON null. This API takes
already verified JSON. Signature, identity, duplicate JSON member detection
and trust-anchor checks belong to the caller.

An immediate superior can override a leaf's metadata parameters. Every
superior can restrict them through policy. The library checks critical
operator declarations before merging, then applies the combined policy to
the leaf's metadata. It supports the seven standard operators. An unknown
optional operator may be ignored, but an unsupported critical declaration
returns an error even if another statement is the only one using it.

A resolver should discard a candidate path on error and try any remaining
paths before returning a failure. Applications using the two-policy merge
helper directly must also check critical declarations from the enclosing
statements. See [the 0.9.0 release notes](CHANGELOG.md).
