# How to Contribute

Thanks for your interest in contributing to the Foundation-AI
`Detection Rule Classifier`! Here are a few general guidelines on contributing
and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
endeavor to review incoming issues and pull requests within 10 days, and will
close any lingering issues or pull requests after 60 days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/cisco-foundation-ai/detection-rules/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and, as
we follow semantic versioning, we may reserve breaking changes until the next
major version release.

### Testing Requirements

All pull requests must include tests for new functionality or bugfixes. Here's
how to work with tests:

**Running Tests Locally:**

```bash
# Install development dependencies
pip install -e .[all]

# Run all tests
pytest

# Run with coverage report
pytest --cov --cov-report=term-missing

# Run specific test file
pytest visualization/tests/test_data_processing.py
```

**Test Coverage Goals:**

- New code should maintain or improve overall coverage (currently 97%)
- Core data processing functions should have 90%+ coverage
- All aggregation logic must have 100% coverage

**Adding New Tests:**

- Place tests in `visualization/tests/`
- Use descriptive test names that explain what is being tested
- Follow existing test patterns in `test_data_processing.py`, `test_charts.py`,
  or `test_app_rendering.py`
- Use pytest markers appropriately:
  - `@pytest.mark.unit`: Unit tests for individual functions
  - `@pytest.mark.integration`: Integration tests for data pipeline stages
  - `@pytest.mark.visual`: Visual tests for Streamlit UI components
  - `@pytest.mark.slow`: Tests that take longer to run (>1 second)
- Mock external dependencies (MITRE mapper, file I/O, etc.)

**Test Categories:**

- **Unit tests**: Test individual functions in isolation (e.g.,
  `test_data_processing.py`, `test_charts.py`)
- **Integration tests**: Test data pipeline stages and interactions
- **Visual tests**: Test Streamlit UI components using AppTest framework
  (e.g., `test_app_rendering.py`)

See [CLAUDE.md](CLAUDE.md#testing) for detailed testing documentation.

### Linting Code

This project uses GitHub Super-Linter with custom configurations. All pull
requests must pass linting checks before being merged.

**Running Linters Locally:**

You can run most linters locally to catch issues before pushing, saving time
waiting for the GitHub Actions report:

```bash
# Python code formatting
black .

# Python import sorting
isort --settings-path .github/linters/.isort.cfg .

# Python code style (ignore specific rules)
flake8 . | grep -ev "E203|E501"

# Python linting
ruff check .
pylint --rcfile .github/linters/.python-lint .

# YAML linting
yamllint -c .github/linters/.yamllint.yml .

# Security scanning
trivy fs --config .github/linters/.trivy.yml .
```

**Linting Standards:**

- Code must pass all configured linters before PR approval
- Some linter rules are customized in `.github/linters/` configs
- If you believe a linter rule should be adjusted, open an issue for
  discussion

## Other Ways to Contribute

We welcome anyone that wants to contribute to `Detection Rule Classifier` to
triage and reply to open issues to help troubleshoot and fix existing bugs.
Here is what you can do:

- Help ensure that existing issues follows the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review and update the existing content of our
  [Cookbooks](https://github.com/cisco-foundation-ai/detection-rules/cookbook)
  with up-to-date instructions and code samples.
- Review existing pull requests, and testing patches against real existing
  applications that use `Detection Rule Classifier`.
- Write a test, or add a missing test case to an existing test.

Thanks again for your interest on contributing to `Detection Rule Classifier`!

:heart:
