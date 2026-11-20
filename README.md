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

## Preparing metadata and policy documents

Each role in a leaf or superior's `metadata` claim must contain a JSON
object. An empty role object is valid. Each parameter directly inside a role
must have a non-null value, even if an override would replace it or if the
role belongs to an intermediate. A parameter can contain nested JSON such
as `{"settings": {"fallback": null}}`. To remove a parameter through policy,
use the `value` operator with a null operand.

For both document APIs, omit `metadata_policy` when no policy applies.
When upgrading to 0.9.0, callers that passed `"metadata_policy": {}` to
`apply_policy_document_on_metadata` must remove that member. A document
containing only `metadata` can still supply overrides.

`merge_policies` omits parameters and roles whose operators were all
ignored. When reissuing a merged policy, include the map only if it contains
at least one role. An empty result means the claim should be omitted.

## Operator edge cases

- Applying `add` deduplicates the existing array as well as the additions.
  For example, applying `{"add": []}` to `["a", "a"]` yields `["a"]`.
  This also applies when all proposed additions are already present.
- Numeric comparisons use `serde_json::Value` equality. For example,
  `{"one_of": [1]}` rejects the JSON number `1.0`. The same distinction
  applies when merging `value` or `default` operands and when performing
  array unions, intersections, or membership checks. Use a consistent
  number representation across policies and metadata.
