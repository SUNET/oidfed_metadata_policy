# 0.9.0 - 2026-11-20

## Added

- Add `SubordinatePolicy` and `resolve_chain_metadata` for resolving a
  verified chain in anchor-to-leaf order. The resolver checks critical
  operator declarations across the chain before merging policies, then
  applies the immediate superior's metadata overrides before the merged
  policy.
- Add `validate_metadata_policy_crit` for callers that merge policies
  directly and need to validate critical operator declarations.

## Changed

- Omit `metadata_policy` when a statement has no policy. Both
  `apply_policy_document_on_metadata` and `resolve_chain_metadata` reject
  an explicitly empty claim. A statement may still supply metadata overrides.
- Validate leaf metadata and metadata from every subordinate statement
  before applying overrides. Each role must be an object, and its direct
  parameters must have non-null values. Empty role objects, nested nulls,
  and the `value: null` policy operator for removing a parameter are supported.
- Process OAuth client `scope` as individual tokens and return a
  space-delimited string. Resolution fails if a present scope resolves to
  zero tokens. An absent optional scope may stay absent.

## Fixed

- Validate each policy and its merged result, including rules supplied only
  by the trust anchor or for roles absent from the leaf. Malformed operands,
  incompatible operator combinations, and unsupported critical operators
  invalidate the candidate chain.
- Preserve rules that a subordinate adds for new parameters of an existing
  role. Merge `one_of` and `subset_of` by intersection, `add` and
  `superset_of` by union, and `essential` by logical OR.
- Return a policy error when `add` receives scalar metadata.
- Drop parameters and roles left empty after ignoring optional extension
  operators. If the entire merged policy is empty, omit the claim when
  issuing a statement.
