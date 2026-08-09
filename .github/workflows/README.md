# GitHub Workflows

GitHub Actions workflow definitions for repository automation.

## Current workflow

- `quarto-publish.yml` — builds/publishes the Quarto project defined by `_quarto.yml` and `Capstone-intro.qmd`.

Keep workflow secrets and environment-specific credentials in GitHub Actions secrets, not in committed YAML.
