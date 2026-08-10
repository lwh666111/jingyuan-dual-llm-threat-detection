# Fast defense rule notice

The fast-path rule categories and scoring design are aligned with the OWASP
Core Rule Set (CRS) paranoia-level 1 philosophy: only high-confidence,
structural attack evidence is eligible for immediate IP enforcement.

This project does not present fast-path matches as AI alerts. Matches are kept
in an internal audit table, while the original detection and situation pipeline
continues processing the same request independently.

Reference: https://github.com/coreruleset/coreruleset

OWASP CRS is licensed under the Apache License 2.0. The expressions in
`fast_defense_rules.json` are project-specific rules and are not a verbatim copy
of the CRS SecLang files.
