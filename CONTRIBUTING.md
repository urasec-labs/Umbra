# Contributing

Umbra is a **defensive** tool. Contributions that improve detection quality, remediation guidance, reliability and tests are welcome.
Offensive-only features (exploitation, credential attacks, evasion) are out of scope.

1. Open an issue describing the check or problem.
2. `pip install -r requirements.txt ruff && pre-commit install` (optional)
3. Add a module under `modules/` (see `plugins/_example_security_txt.py`) and **test it against the local lab** in `tests/test_umbra.py`.
4. Every finding needs a stable `rule` id, a `remediation`, and a `fix_snippet` when a config change fixes it.
5. `ruff check . && python -m unittest discover -s tests` must pass.
6. Never include real credentials, private hostnames or scan output in issues/PRs.
