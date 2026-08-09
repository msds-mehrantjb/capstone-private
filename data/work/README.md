# Working Audit State

Mutable, year-scoped application data generated and updated by the audit workflow.

Each audit year has its own subfolder, for example:

```text
2026/
```

The backend reads/writes these files during normal use. Avoid hand-editing active audit state unless you understand the expected schema and downstream dependencies.
