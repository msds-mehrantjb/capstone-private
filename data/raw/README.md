# Raw Folder

This folder stores baseline raw JSON files that are used as starting points or reference versions.

---

## `Dashboard.json`

`Dashboard.json` is the base dashboard source file.

It provides the raw dashboard structure that the backend reads and normalizes before returning dashboard data to the frontend.

In practice, the backend combines this base dashboard file with:

- system status
- workflow JSON files in `data/work/<year>/`
- scope data
- KPI calculations

So `Dashboard.json` is the base dashboard definition, not the full live state by itself.

---

## Meaning of `*-v0.json`

Files ending with `-v0.json` are **baseline template versions**.

Example:

- `2026-Scope-v0.json`
- `2026-Scope-Draft-v0.json`
- `2026-Scope-Financial-v0.json`
- `2026-Scope-Healthcare-v0.json`
- `2026-Scope-Sample-v0.json`

`v0` means:

- initial template
- baseline starting point
- not a submitted working version

These files are used when the system needs to:

- reset a document to its starting state
- create a new draft from a baseline
- provide a sample or predefined starting template

---

## Versioning Rule

The versioning pattern is:

- `v0` = baseline template
- `v1`, `v2`, `v3`, ... = saved working versions created later

Example:

- `2026-Scope-v0.json` -> baseline
- `2026-Scope-v11.json` -> later saved version

So the important distinction is:

- `v0` = template / reset point
- `v1+` = actual saved versions created during use

---

## Practical Meaning in the App

For scope documents especially:

- `v0` should be treated as the baseline template
- non-`v0` versions represent real saved versions

That is why the application often uses `v0` to decide whether a scope document is still only a template or has progressed into an actual saved working document.
