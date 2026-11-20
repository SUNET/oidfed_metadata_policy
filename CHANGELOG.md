# 0.9.0 - 2026-11-20

- Add `resolve_chain_metadata` for resolving verified subordinate statements
  in anchor-to-leaf order. It checks critical operator declarations across
  the chain before merging policies and applies the immediate superior's
  metadata before applying the resolved policy.
- Reject malformed policy structures, invalid standard operator operands
  and incompatible combinations, including rules for roles absent from the
  leaf. Optional unknown operators are ignored. Unsupported mandatory
  operators invalidate the candidate chain.
- Retain subordinate rules for new parameters of an existing entity type.
  Merge intersecting allowed sets and required sets across superiors.
  Evaluate `essential` as a boolean and report metadata type errors to the
  caller.
- Apply OAuth client `scope` policies to individual scope tokens and
  serialize the resolved set as a space-delimited string. Other roles can
  define their own `scope` parameter.
