# sqlsec — Label-Based Security for SQLite

`sqlsec` is a SQLite extension that implements **row-level and column-level security** using **security labels**, **logical views**, and **context attributes**.

It allows you to:

* Restrict **which rows** a user can see
* Restrict **which columns** a user can see
* Conditionally **hide entire tables**
* Safely allow **INSERT / UPDATE / DELETE** through secure views
* Express access rules using **boolean expressions over attributes**

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
role=admin & team=finance
(role=admin | role=auditor)
```

Labels are defined once and referenced by ID.

---

### Security context

A *security context* is a set of key/value attributes:

```sql
role = admin
team = finance
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
SELECT sec_define_label('true');                    -- public
SELECT sec_define_label('role=admin');
SELECT sec_define_label('role=admin & team=finance');
SELECT sec_define_label('(role=admin | role=auditor)');
```

Each call returns a **label ID**.

---

## Registering a Secured Table

```sql
SELECT sec_register_table(
    'employees',        -- logical view name
    '__sec_employees',  -- physical table name
    'row_label_id',     -- row label column
    NULL,               -- optional table-level label
    NULL                -- optional insert label
);
```

This:

* Registers metadata
* Auto-discovers columns
* Creates a logical view on refresh

---

## Column-Level Security

Each column can have its own label:

```sql
UPDATE sec_columns
SET label_id = sec_define_label('role=manager')
WHERE logical_table = 'employees'
  AND column_name = 'salary';
```

If a column is not visible:

* It is **omitted entirely** from the view
* Queries never see it

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

### Refresh views

```sql
SELECT sec_refresh_views();
```

> **Important:**
> You must call `sec_refresh_views()` after changing context attributes.

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

## Column-Level Security Example

```sql
UPDATE sec_columns
SET label_id = sec_define_label('role=admin')
WHERE column_name = 'ssn';
```

Results:

| Role    | Visible columns      |
| ------- | -------------------- |
| user    | id, name, email      |
| auditor | id, name, email      |
| admin   | id, name, email, ssn |

---

## INSERT, UPDATE, DELETE Support

Writes go through **INSTEAD OF triggers** on the logical view.

### INSERT

```sql
INSERT INTO customers (id, name, email)
VALUES (1, 'Alice', 'alice@example.com');
```

* Automatically routed to the physical table
* Row label is set via `row_label_id`

---

### UPDATE

```sql
UPDATE inventory
SET quantity = 20
WHERE item = 'Apples';
```

* Allowed only for visible rows
* Uses the table’s primary key (auto-detected)
* Primary keys cannot be modified

---

### DELETE

```sql
DELETE FROM inventory
WHERE item = 'Oranges';
```

* Deletes only rows visible in the current context

---

## Composite & Complex Labels

Labels support full boolean logic:

```sql
SELECT sec_define_label('(role=admin | role=auditor)');
```

Combined with context attributes:

```sql
SELECT sec_set_attr('role', 'auditor');
```

---

## Requirements & Constraints

* Each secured table **must have a primary key**
* Each secured table **must have a row label column**
* Applications **must query logical views**
* Context changes require `sec_refresh_views()`

---

## Summary

`sqlsec` provides:

* Row-level security
* Column-level security
* Table-level visibility
* Safe write support
* Declarative access rules

All implemented using:

* SQLite views
* Triggers
* Context-aware label evaluation

No application-side filtering required.
