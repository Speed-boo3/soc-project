# Contributing

Thanks for taking a look at this project. Here is how to get started if you want to contribute.

---

## Getting set up

```bash
git clone https://github.com/Speed-boo3/soc-project.git
cd soc-project
pip install -r requirements.txt
```

## Running the tests

```bash
pytest tests/
```

All tests should pass before you open a pull request.

## Adding a new detection rule

Rules live in `soc/alert-rules/rules.yaml`. Each rule needs:
- A unique ID (e.g. `RULE-007`)
- A name and description
- A condition with a field, match type and threshold
- A severity level: `low`, `medium` or `high`
- A MITRE ATT&CK technique ID and tactic

## Reporting a bug

Open an issue and describe what happened, what you expected, and how to reproduce it.
