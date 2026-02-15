# sqlsec - Label-Based Security for SQLite

`sqlsec` is a SQLite extension that implements **row-level and column-level security** using **security labels**, **logical views**, and **context attributes**.

It allows you to:

* Restrict **which rows** a user can see
* Restrict **which columns** a user can see
* Restrict **which columns** a user can update
* Conditionally **hide entire tables**
* Safely allow **INSERT / UPDATE / DELETE** through secure views
* Express access rules using **boolean expressions over attributes**
* Enforce **MLS-style clearance levels** with dominance relationships

All enforcement happens *inside SQLite*, using views and triggers.

---

## High-Level Design

### Physical tables

You store real data in *physical tables* (usually prefixed with `__sec_`).

Each secured table must include a **row label column**:

```sql
row_label_id INTEGER NOT NULL
```

This column references a security label that controls row visibility.

---

### Logical views

For each registered table, `sqlsec` creates a **logical view**:

```sql
employees  →  __sec_employees
```

Applications query the logical view, **never the physical table**.

The view:

* Filters rows based on row labels
* Filters columns based on column labels
* Exists only if the table is visible to the current context

---

### Security labels

Labels are boolean expressions over context attributes:

```sql
true
role=admin
role=admin&team=finance
(role=admin|role=auditor)
clearance>=secret
```

Labels are defined once and referenced by ID.

---

### Security context

A *security context* is a set of key/value attributes:

```sql
role = admin
team = finance
clearance = top_secret
```

The active context determines which labels evaluate to `true`.

---

## Loading the Extension

```sql
.load ./libsqlsec
```

> The shared library name may vary depending on platform and build mode.

---

## Defining Labels

Define labels using boolean expressions:

```sql
SELECT sec_define_label('true');                       -- public
SELECT sec_define_label('role=admin');
SELECT sec_define_label('role=admin&team=finance');
SELECT sec_define_label('(role=admin|role=auditor)');
```

Each call returns a **label ID**.

### Label Expression Syntax

| Expression | Meaning |
| --- | --- |
| `true` | Always visible |
| `key=value` | Attribute must match exactly |
| `a&b` | Both conditions must be true (AND) |
| `(a\|b)` | Either condition must be true (OR) |
| `key>=value` | Level comparison (requires defined levels) |

---

## Level-Based Security (MLS)

For military/compliance-grade models, define clearance levels:

```sql
-- Define levels (higher value = more access)
SELECT sec_define_level('clearance', 'public', 0);
SELECT sec_define_level('clearance', 'confidential', 1);
SELECT sec_define_level('clearance', 'secret', 2);
SELECT sec_define_level('clearance', 'top_secret', 3);
```

Then use comparison operators in labels:

```sql
SELECT sec_define_label('clearance>=secret');
```

### Supported Comparison Operators

| Operator | Meaning |
| --- | --- |
| `=` | Equal |
| `>=` | Greater than or equal |
| `>` | Greater than |
| `<=` | Less than or equal |
| `<` | Less than |

A user with `clearance=top_secret` can access rows labeled `clearance>=secret` because `3 >= 2`.

---

## Registering a Secured Table

```sql
SELECT sec_register_table(
    'employees',        -- logical view name
    '__sec_employees',  -- physical table name
    'row_label_id',     -- row label column
    NULL,               -- optional table-level label
    NULL                -- optional insert-permission label
);
```

This:

* Registers metadata
* Auto-discovers columns
* Creates a logical view on refresh

---

## Column-Level Security

### Read Security

Each column can have a read label:

```sql
UPDATE sec_columns
SET read_label_id = sec_define_label('role=manager')
WHERE logical_table = 'employees'
  AND column_name = 'salary';
```

If a column is not visible:

* It is **omitted entirely** from the view
* Queries never see it

### Update Security

Each column can have an update label:

```sql
UPDATE sec_columns
SET update_label_id = sec_define_label('role=hr')
WHERE logical_table = 'employees'
  AND column_name = 'title';
```

If a column is not updatable:

* UPDATE statements that modify it will be rejected
* Columns without an update_label_id can be updated by anyone who can see the row

### Combined Example

```sql
UPDATE sec_columns
SET read_label_id = sec_define_label('role=admin'),
    update_label_id = sec_define_label('role=auditor')
WHERE column_name = 'ssn';
```

Results:

| Role    | Visible columns      | Updatable columns    |
| ------- | -------------------- | -------------------- |
| user    | id, name, email      | id, name, email      |
| auditor | id, name, email      | id, name, email, ssn |
| admin   | id, name, email, ssn | id, name, email      |

---

## Table-Level Security

You can hide an entire table unless a label matches:

```sql
SELECT sec_register_table(
    'reports',
    '__sec_reports',
    'row_label_id',
    sec_define_label('role=admin'),
    NULL
);
```

If the label is not visible:

* The logical view does not exist
* `.tables reports` returns nothing

---

## Managing the Security Context

### Clear the context

```sql
SELECT sec_clear_context();
```

### Set attributes

```sql
SELECT sec_set_attr('role', 'admin');
SELECT sec_set_attr('team', 'finance');
```

Attributes are **multi-valued** - calling `sec_set_attr` with the same key adds to the set:

```sql
SELECT sec_set_attr('role', 'admin');
SELECT sec_set_attr('role', 'manager');
-- User now has both role=admin AND role=manager
```

### Push/Pop a context scope

```sql
SELECT sec_set_attr('role', 'user');
-- role is user

SELECT sec_push_context();
    SELECT sec_set_attr('role', 'admin');
    -- role is admin
SELECT sec_pop_context();

-- role is user again
```

### Refresh views

```sql
SELECT sec_refresh_views();
```

> **Important:**
> You must call `sec_refresh_views()` after changing context attributes.

### Assert freshness

```sql
SELECT sec_assert_fresh();
```

Returns 1 if views are fresh, raises an error if stale. Used internally by triggers.

---

## Row-Level Security

Rows are filtered automatically:

```sql
SELECT * FROM employees;
```

Only rows whose `row_label_id` evaluates to `true` in the current context are visible.

Example:

| Context                    | Visible rows       |
| -------------------------- | ------------------ |
| `role=user`                | Public rows        |
| `role=admin`               | Admin rows         |
| `role=admin, team=finance` | Finance-admin rows |

---

## INSERT, UPDATE, DELETE Support

Writes go through **INSTEAD OF triggers** on the logical view.

### INSERT

```sql
INSERT INTO customers (id, name, email)
VALUES (1, 'Alice', 'alice@example.com');
```

* Automatically routed to the physical table
* Row label is set automatically based on `insert_label_id` or `table_label_id`

### UPDATE

```sql
UPDATE inventory
SET quantity = 20
WHERE item = 'Apples';
```

* Allowed only for visible rows
* Uses the table's primary key (auto-detected)
* **Primary keys cannot be modified**
* **Row label column cannot be modified**
* Column update policies are enforced

### DELETE

```sql
DELETE FROM inventory
WHERE item = 'Oranges';
```

* Deletes only rows visible in the current context

---

## Stale View Protection

If the security context changes without refreshing views, all operations are blocked:

```sql
SELECT sec_set_attr('role', 'admin');
-- Forgot to call sec_refresh_views()

SELECT * FROM employees;
-- Error: security views are stale: call sec_refresh_views()
```

---

## Requirements & Constraints

* Each secured table **must have a primary key**
* Each secured table **must have a row label column**
* `WITHOUT ROWID` tables are **not supported**
* Applications **must query logical views**, never physical tables
* Context changes require `sec_refresh_views()`

---

## Function Reference

| Function | Arguments | Description |
| --- | --- | --- |
| `sec_define_label` | expr | Define a label expression, returns label ID |
| `sec_define_level` | attr, name, value | Define a level for comparison operators |
| `sec_register_table` | logical, physical, row_col, table_label, insert_label | Register a secured table |
| `sec_set_attr` | key, value | Add an attribute to the context |
| `sec_clear_context` | - | Clear all context attributes |
| `sec_push_context` | - | Save current context to stack |
| `sec_pop_context` | - | Restore context from stack |
| `sec_refresh_views` | - | Rebuild views for current context |
| `sec_assert_fresh` | - | Assert views are not stale |
| `sec_label_visible` | label_id | Check if a label is visible (internal) |

---

## Summary

`sqlsec` provides:

* Row-level security
* Column-level read security
* Column-level update security
* Table-level visibility
* MLS-style level dominance
* Safe write support via triggers
* Declarative access rules
* Scoped context with push/pop

All implemented using:

* SQLite views
* INSTEAD OF triggers
* Context-aware label evaluation

No application-side filtering required.
