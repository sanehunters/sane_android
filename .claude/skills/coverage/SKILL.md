---
name: coverage
description: Show two-dimensional coverage and check the P7 gate.
---

# /coverage [--gate p7]

`python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory/ [--gate p7]`.
The gate exits non-zero while any breadth row (every domain except D26/D27) or any instance is untested, or any `n/a` row lacks a reason. Fix the listed rows; do not argue with the gate.
