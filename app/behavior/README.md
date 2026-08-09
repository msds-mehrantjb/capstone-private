# User Behavior Processing

User-activity behavior collection and aggregation used by risk analysis and AI/ML telemetry.

## Contents

- `Agent/` — PowerShell-based workstation collection/install scripts.
- `aggregate_user_behavior.py` — combines collected activity into the central behavior dataset.
- `BehaviorAgent_Technical_Document.md` — design and implementation notes.

Generated/aggregated audit data is written under `data/work/<year>/`.
