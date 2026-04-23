# `app/src`

This folder contains the frontend application source code.

It is the React + TypeScript UI layer for the Capstone project and includes:

- page components for each ISO 27001 workflow stage
- the main app shell and routing entry
- shared frontend styling files

## Main files

- `main.tsx`  
  Frontend entry point.

- `App.tsx`  
  Main application shell and route wiring.

- `App.css`  
  App-level styling.

- `index.css`  
  Global styling.

## Main folder

- `pages/`  
  Page-level components for the dashboard, workflow pages, Final Deliverables, and AI/ML dashboard.

## What lives in `pages`

The `pages` folder contains the main user-facing workflow screens, including:

- Dashboard
- Scope & Context
- Asset Inventory & CIA
- Threats & Vulnerabilities
- Existing Controls & Postures
- Risk Analysis
- Risk Evaluation / Treatment
- Annex A & SoA
- Action Plan / Implementation
- Monitoring & Improvement
- Final Deliverables
- AI/ML Dashboard

## How this folder works with the backend

Most pages in `pages/` call matching route modules in:

- `app/api`

Those APIs read and update working audit files in:

- `data/work/2026`

## Notes

- Most command-mode assistant behavior is implemented inside the page components in `pages/`.
- The frontend is built with Vite and TypeScript.
- Use this folder for UI code only; backend logic belongs in `app/api`.
