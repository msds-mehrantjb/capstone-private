# Frontend Source

React + TypeScript frontend for the ISO 27001 audit application.

## Main files

- `main.tsx` — React bootstrap and global stylesheet imports.
- `App.tsx` — hash-based page routing/application shell.
- `pages/` — workflow and dashboard page components.
- `index.css` — global/layout overrides.
- `active-menu.css` — shared active-navigation styling.
- `scope-context-layout.css` — Scope & Context desktop spacing/layout rules.

The frontend reads `VITE_API_BASE_URL`; the startup script supplies `http://127.0.0.1:8002`.
