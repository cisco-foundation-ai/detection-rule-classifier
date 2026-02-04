# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

Detection Rules Classifier - A framework for automatically mapping security
detection rules to the MITRE ATT&CK framework and Cyber Kill Chain. Three core
components:

1. **rules_fetcher**: Clones detection rule repositories (default: Splunk
   Security Content) and processes YAML rule files, removing MITRE tags to
   prepare for classification
2. **classification**: AI-powered pipeline using OpenAI/HuggingFace LLMs to
   classify detection rules with MITRE ATT&CK techniques
3. **visualization**: Streamlit dashboard for interactive exploration of
   classified rules and techniques

## Quick Development Commands

### Environment Setup

**IMPORTANT**: Always use the virtual environment located at `venv/` in the root
project folder. Activate it before running any commands:

```bash
# From the root project folder (detection-rules/)
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate  # On Windows

# Install dependencies based on your needs:

# Option 1: Full installation (all features, ~2-3 GB with
# torch/transformers)
pip install -e .[all]

# Option 2: Visualization only (lightweight, ~200 MB)
pip install -e .[viz]

# Option 3: Classification only (ML dependencies)
pip install -e .[classificaiton]

# Option 4: Modular install (visualization + classification)
pip install -e .[classificaiton,viz]

# Set required API keys (only needed for classification)
export OPENAI_API_KEY="your-key-here"
export HUGGINGFACE_KEY="your-hf-key-here"  # Optional
```

**Requirements Files**:

- `requirements.txt` - Full installation (all components)
- `requirements-viz.txt` - Lightweight visualization dashboard only
- `requirements-classification.txt` - ML dependencies (torch,
  transformers, openai)
- `requirements-dev.txt` - Development/testing tools

All Python commands below assume the venv is activated and you're in
the root project directory.

### Linting

The project uses GitHub Actions with super-linter. Key configurations:

- Pylint: `.python-lint`
- Flake8: `.flake8`
- Ruff: `.ruff.toml`
- MyPy: `mypy.ini`
- YAML: `.yamllint.yml`
- Markdown: `.markdownlint.yml`

Run type checking locally:

```bash
python -m mypy classification rules_fetcher mitre_mapping visualization
```

### Complete Pipeline Workflow

```bash
# 1. Fetch detection rules
python -m rules_fetcher.rules_fetcher

# 2a. Classify with single-step approach (faster)
# By default, automatically merges existing MITRE labels from original rules
python -m classification.pipeline \
  --config classification/config_example_one_step.json \
  --input-path output/rules/untagged \
  --output-file-path output/classification/classified_output.json

# 2b. Classify with two-step approach (recommended for accuracy)
# By default, automatically merges existing MITRE labels from original rules
python -m classification.pipeline \
  --config classification/config_example_two_step.json \
  --input-path output/rules/untagged \
  --output-file-path output/classification/classified_output.json

# 2c. (Optional) Disable original merging if you only want AI predictions
python -m classification.pipeline \
  --no-merge-existing-labels \
  --config classification/config_example_two_step.json

# 2d. (Optional) Standalone merge tool for advanced use cases
python -m classification.merge_original_labels \
  --classifier-output output/classification/classified_output.json \
  --original-rules-folder output/rules/original \
  --output output/classification/classified_output_merged.json

# 3. Generate aggregations (pre-compute statistics and correlations)
python -m aggregation.pipeline --config aggregation/config_aggregation.json

# 4. (Optional) Generate LLM-powered insights
export OPENAI_API_KEY="your-key-here"
python -m aggregation.insights_generator --config aggregation/config_insights.json

# 5. Launch visualization dashboard
# Option A: With your own data
streamlit run visualization/app.py \
  -- --classified-output-file-path output/aggregation/aggregated_data.json

# Option B: Quick demo with sample data (no setup required)
streamlit run visualization/app.py
```

**Note**: The visualization app automatically falls back to demo data from
`aggregation/demo/` when no user data exists in `output/aggregation/`. This
allows developers to explore the visualization immediately after cloning the
repository.

## Architecture and Data Flow

### Directory Structure

```text
detection-rules/
├── rules_fetcher/         # Rule ingestion and preprocessing
├── classification/        # AI-powered MITRE mapping
│   ├── pipeline.py        # Main orchestration
│   ├── utils.py           # LLM providers, parsing, config
│   └── merge_original_labels.py  # Merge AI predictions with
│                               # human labels├── aggregation/           # Data aggregation and insights generation
│   ├── pipeline.py        # Aggregation orchestration
│   ├── data_processor.py  # Statistics and correlation computation
│   ├── insights_generator.py  # LLM-powered insights (optional)
│   ├── prompts.py         # LLM prompt templates
│   └── demo/              # Sample data for quick exploration
│       ├── aggregated_data.json
│       ├── insights.json
│       └── config.json

├── mitre_mapping/         # MITRE ATT&CK taxonomy management
│   └── mitre_attack_mapper.py  # Caching, technique/tactic/
│                                # kill-chain mapping
├── visualization/         # Streamlit web dashboard
│   └── app.py
└── output/                # Generated artifacts
    ├── rules/
    │   ├── original/      # Cloned repo rules (with MITRE tags)
    │   └── untagged/      # Processed rules (MITRE tags removed)
    └── classification/
        └── classified_output.json  # Classification results
```

### Classification Pipeline Architecture

**Two-Step Classification** (recommended):

1. **Plausible Step**: Broad filtering from ~600 techniques → top 10 plausible
   matches
2. **Relevant Step**: Refined selection from plausible set → top 1-3 most
   relevant techniques

This reduces false positives by first casting a wide net, then narrowing down.

**Single-Step Classification**: Directly identifies top 3 relevant techniques
from all ~600 techniques (faster but less precise).

**Configuration**: JSON files control the pipeline behavior:

- `classification/config_example_one_step.json`: Single-step mode
- `classification/config_example_two_step.json`: Two-step mode with
  plausible/relevant phases

Each step configuration includes:

- `provider`: "openai" or "huggingface"
- `model`: Model identifier (e.g., "gpt-4o")
- `top_k`: Number of techniques to return
- `prompt`: Classification prompt template
- `use_short_descriptions`: Boolean for technique description verbosity

**SSL Certificate Workaround**: Use `--disable-ssl-verify` flag if
encountering SSL certificate verification issues in proxy-restricted
environments.

### MITRE ATT&CK Mapping Module

`mitre_mapping/mitre_attack_mapper.py` provides the taxonomy backbone:

- Fetches MITRE ATT&CK STIX data using `mitreattack-python` library
- Caches data locally in `mitre_attack_cache.json` for performance
- Maps techniques → tactics → Cyber Kill Chain stages
- Provides dataclasses: `Technique`, `SubTechnique`, `Tactic`,
  `CyberKillChainStage`
- Cyber Kill Chain mapping defined in `cyber_kill_chain_mapping.json`

Key functions:

- `get_all_techniques()`: Returns all MITRE techniques
- `get_all_sub_techniques()`: Returns all sub-techniques
- `get_mapper()`: Returns initialized `MitreAttackMapper` singleton

### Rules Fetcher Details

`rules_fetcher/rules_fetcher.py`:

- Clones Git repositories containing detection rules
- Default: Splunk Security Content
  (`https://github.com/splunk/security_content`)
- Pattern matching: `detections/**/*.yml` by default
- Processes YAML files by removing MITRE tags
  (`tags.mitre_attack_id`) to create untagged versions for blind
  classification
- Saves original rules to `output/rules/original/` and untagged to
  `output/rules/untagged/`
- Includes optional rules list filtering via `--rules-list-file` (see
  `default_rules_list.txt`)

### Original Merging

**Default Behavior**: The classification pipeline (`classification/pipeline.py`)
**automatically merges** existing MITRE labels from original rules with AI
predictions by default.

**Integration**: After classification completes, the pipeline:

1. Checks if `output/rules/original/` exists
2. Extracts MITRE tags from original YAML files
3. Merges them with classifier predictions using set union
4. Outputs a single file with complete data

**Control Flags**:

- `--no-merge-existing-labels`: Disable merging (AI predictions only);
  default is to merge
- `--original-rules-folder`: Custom path to original rules (default:
  `output/rules/original`)

**Standalone Tool** (`classification/merge_original_labels.py`):

- Available for advanced use cases (re-merging, custom workflows)
- Same merging logic as the pipeline integration
- **Format assumption**: Designed for Splunk security content YAML
  format with `tags.mitre_attack_id` field
- Other formats (e.g., Sigma rules) require modifications to
  `extract_mitre_ids_from_yaml_rule()`

### Visualization Dashboard

`visualization/app.py` (Streamlit):

- Loads classification results from JSON
- Enriches with MITRE taxonomy data (technique names, descriptions,
  tactics, kill-chain stages)
- Provides interactive tables, charts, and filters
- Supports loading from local files or HTTP/HTTPS URLs
- Default file: `output/classification/classified_output.json`

`visualization/charts.py`:

- Chart creation functions using Altair library
- `create_tactic_coverage_chart()`: Stacked bar chart showing rule
  mappings per tactic
- `create_kill_chain_coverage_chart()`: Bar chart showing kill chain
  stage coverage
- `create_tactic_killchain_heatmap()`: Heatmap showing tactic/
  kill-chain intersections
- `create_top_techniques_chart()`: Bar chart showing top 20 techniques
  by rule count

**Canonical Tactic Ordering**: Dashboard uses official MITRE ATT&CK
Enterprise tactic order (Reconnaissance → Resource Development →
Initial Access → ... → Impact)

## Output Formats

### Classification Output (`classified_output.json`)

```json
[
  {
    "id": "rule_id_1",
    "plausible": ["T1059", "T1105", "T1566"], // Only in two-step mode
    "relevant": ["T1059", "T1105"]
  }
]
```

### Rules Data

- **Input**: YAML files with detection rule content
- **Processed**: DataFrame with `rule_id` and `file_content` columns
- Supports both Parquet files and directory of YAML files

## MyPy Configuration

`mypy.ini` includes special handling:

- Explicit package bases with namespace packages enabled
- Per-package configuration for `classification`, `mitre_mapping`,
  `rules_fetcher`, `visualization`
- Ignores workspace-level module conflicts to prevent import issues

## Dependencies

Dependencies are split into modular files for flexible installation:

**requirements-viz.txt** (Lightweight ~200 MB):

- **Data Processing**: `pandas`, `pyarrow`, `pyyaml`, `httpx`
- **Visualization**: `streamlit`, `altair`
- **MITRE Mapping**: `mitreattack-python` (provides STIX 2.0 data
  access)

**requirements-classification.txt** (Heavy ~2-3 GB):

- **ML Frameworks**: `torch`, `transformers`
- **LLM API**: `openai`

**requirements.txt** - Full installation (includes both above)

Python 3.10+ required

## Testing

### Running Tests

Tests are located in `visualization/tests/` with 97% overall coverage
(68 tests total).

```bash
# Install development dependencies
pip install -e .[all]

# Run all tests
pytest

# Run with coverage report
pytest --cov --cov-report=term-missing

# Run specific test file
pytest visualization/tests/test_data_processing.py

# Run specific test class
pytest visualization/tests/test_data_processing.py::TestSortTactics

# Run specific test
pytest visualization/tests/test_data_processing.py::TestSortTactics::test_canonical_order

# Run tests in parallel (faster)
pytest -n auto
```

### Test Organization

- **`visualization/tests/test_data_processing.py`**: 39 tests for core
  data processing functions
  - `sort_tactics()`: Canonical MITRE tactic ordering
  - `load_detection_rules()`: JSON file/URL loading
  - `enrich_technique_data()`: Technique enrichment with MITRE data
  - `enrich_tactic_data()`: Tactic enrichment
  - `enrich_kill_chain_data()`: Kill chain enrichment
  - Data pipeline integration (6 tests)
  - Aggregation correctness (8 tests) - HIGH PRIORITY
  - `parse_args()`: CLI argument parsing

- **`visualization/tests/test_charts.py`**: 19 tests for chart
  creation functions
  - `create_tactic_coverage_chart()`: Validates bar chart
    specifications
  - `create_kill_chain_coverage_chart()`: Validates kill chain bar
    chart
  - `create_tactic_killchain_heatmap()`: Validates heatmap
    specifications
  - `create_top_techniques_chart()`: Validates top techniques chart
  - Tests verify Altair chart encodings, marks, dimensions, and color
    schemes

- **`visualization/tests/test_app_rendering.py`**: 10 tests for
  Streamlit UI components
  - Basic rendering: App runs without errors, title displays, rule
    count shows
  - Chart rendering: All 4 charts render (tactic coverage, kill chain,
    heatmap, top techniques)
  - Data display: Dataframe renders with correct structure
  - Error handling: App handles test data gracefully
  - Performance: App renders within reasonable time (<10 seconds)

- **`visualization/tests/conftest.py`**: Shared pytest fixtures
  - Mock MITRE mapper with test data
  - Sample classification data
  - Streamlit cache disabling
  - DataFrame fixtures for testing aggregations
  - AppTest fixture for UI testing

- **`visualization/tests/fixtures/sample_data.py`**: Mock MITRE ATT&CK
  data
  - 4 techniques (T1059, T1027, T1558, T1098)
  - 3 sub-techniques (T1059.001, T1558.003, T1098.001)
  - 4 tactics (Execution, Defense Evasion, Credential Access,
    Persistence)
  - 3 kill chain stages (Exploitation, Installation, Actions on
    Objectives)

### Test Markers

Use pytest markers to run specific test categories:

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run slow tests
pytest -m slow

# Run visual tests (UI component tests)
pytest -m visual

# Run all except slow tests
pytest -m "not slow"
```

### CI/CD

Tests run automatically on:

- Push to `main` branch
- All pull requests

See `.github/workflows/test.yml` for CI configuration.

### Coverage Goals

- **Overall**: 80%+ (currently 85%)
- **Core data functions**: 90%+ (achieved)
- **Aggregation logic**: 100% (achieved)

### Test Fixtures and Mocking

Tests use comprehensive mocking to avoid external dependencies:

- **MITRE Mapper**: Mocked `get_mapper()` returns fixtures with test
  data
- **Streamlit Cache**: `@st.cache_data` decorator is disabled during
  tests
- **File I/O**: Uses `tmp_path` fixture for temporary JSON files
- **CLI Args**: Mocked via pytest `monkeypatch` fixture

### Debug Logging

The codebase uses debug logging extensively. Use `--debug` flag on CLI
commands for troubleshooting.
