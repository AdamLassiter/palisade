# Roadmap

---

## Tier 1 — Hardening & Completeness (Do These First)

These make the system *correct*, predictable, and production-ready.

---

### 5. Row label assignment policies

Currently:

* INSERT uses `COALESCE(NEW.row_label_id, 1)`

Add:

* Label assignment rules per table
* Default label per table
* Label derived from context

Example:

```sql
SELECT sec_set_insert_policy(
  'employees',
  'role=manager'
);
```

Why:

> Prevents users from forging row labels.

---

### 6. UPDATE policies (beyond visibility)

Add policies like:

* “Column X can only be updated if label Y”
* “Only role=admin can UPDATE salary”

Example:

```sql
SELECT sec_set_update_policy(
  'employees.salary',
  'role=manager'
);
```

Why:

> Visibility ≠ mutability.

---

## Tier 3 — Introspection & Tooling

These improve developer experience and trust.

### 7. Explain security decisions

Add debug functions:

```sql
SELECT sec_explain_row('employees', 1);
SELECT sec_explain_column('employees', 'salary');
```

Return:

* Matched labels
* Failed predicates
* Active context

Why:

> Security systems must be explainable.

---

### 8. Security metadata views

Expose internal tables safely:

```sql
SELECT * FROM sec_tables;
SELECT * FROM sec_columns;
SELECT * FROM sec_labels;
```

Or readonly wrappers:

```sql
CREATE VIEW sec_policy_overview AS ...
```

Why:

> Enables auditing and tooling.

---

## Tier 4 — Performance & Scale

Do this once usage grows.

### 9. Compile labels into bytecode

Right now labels are evaluated dynamically.

Future:

* Parse once
* Compile to an AST
* Cache evaluation plans
* Short-circuit evaluation

Why:

> Massive speedups for large result sets.

---

### 10. Index-aware row filtering

Teach `sec_row_visible()` to:

* Detect static truths
* Push predicates into WHERE clauses
* Enable index usage

Why:

> Avoid full table scans.

---

## Tier 5 — Advanced Security Models

These make `sqlsec` unique.

### 11. Label inheritance / dominance

Support MLS-style dominance:

```sql
label: secret >= confidential >= public
```

Context with higher clearance automatically sees lower data.

Why:

> Enables military / compliance-grade models.

---

### 12. Mandatory Access Control (MAC)

Prevent even admins from bypassing rules.

Example:

* Table-level label is *always enforced*
* Admins cannot see rows above clearance

Why:

> Strong isolation guarantees.

---

### 13. Write auditing & provenance

Automatically log:

* Who modified what
* When
* Under which context

Implementation:

* Trigger-based audit tables

Why:

> Compliance, forensics, accountability.

---

## Tier 6 — Integration & Ecosystem

### 14. SQL syntax sugar

Add helpers:

```sql
GRANT SELECT ON employees.salary TO role=manager;
REVOKE SELECT ON employees.ssn FROM role=user;
```

Translate into label updates internally.

Why:

> Makes the system approachable.

---

### 15. Virtual table frontend

Expose secured data as a virtual table:

* Enables planner cooperation
* Cleaner explain plans

Why:

> Deep SQLite integration.

---

### 16. Policy-as-code export

Allow exporting policies as:

* JSON
* SQL migrations
* Declarative specs

Why:

> CI/CD, reproducibility.

---

## If I Had to Pick the *Best* Next 3

If your goal is **maximum payoff per line of code**:

1. **Row-label assignment policies** (security correctness)
2. **Explain functions** (debuggability & trust)
3. **Context push/pop** (real-world usability)

Those three alone turn this from a clever extension into a **serious security subsystem**.
