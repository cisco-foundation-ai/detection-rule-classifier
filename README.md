# Cisco Foundation AI's LUCID

LLM-driven Understanding, Classification & Insight for Detections

[![Lint](https://github.com/cisco-foundation-ai/detection-rule-classifier/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/marketplace/actions/super-linter)
[![Contributor-Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-fbab2c.svg)](CODE_OF_CONDUCT.md)
[![Maintainer](https://img.shields.io/badge/Maintainer-Cisco-00bceb.svg)](https://opensource.cisco.com)

## About The Project

[LUCID](https://fdtn.ai/blog) is a system for classifying an organization’s
detection rules and generating actionable insights from them.

It enables you to automatically classify security detection rules into
relevant MITRE ATT&CK tactics, techniques, and sub-techniques, as well
as corresponding Cyber Kill Chain stages. These classifications are then
used to generate actionable insights.

**The system, its motivations and methodology are described in detail
in [this blog post](https://fdtn.ai/blog)
([demo here](https://fai-detection-rule-classification.streamlit.app/)).
This repository contains LUCID's source code.**

The LUCID system comprises of four core components:

- [**Rule Fetcher**](rules_fetcher/): Retrieves and prepares detection rules
  from repositories
- [**Classification Pipeline**](classification/): Maps detection rules to
  MITRE ATT&CK techniques using a LLM.
- [**Aggregation and Insights**](aggregation/): Pre-computes data
  transformations, statistical analysis and LLM-based insights.
- [**Visualization Dashboard**](visualization/): Enables interactive
  exploration of rule classifications and insights.

## Super Quick Start (2 Minutes)

Run just the visualization app, using our pre-computed sample detection
rule data.

```bash
# 1. Clone the repository
git clone https://github.com/cisco-foundation-ai/detection-rule-classifier
cd detection-rule-classifier

# 1.5 [Recommended] Use a Python virtual environment
python -m venv .venv && source .venv/bin/activate && \
  pip install --upgrade pip

# 2. Install dependencies (just for the visualization app)
pip install -e '.[viz]'

# 3. Run visualization app (it will open in a new browser window)
python -m streamlit run visualization/app.py
```

## Quick Start (10 Minutes)

Run the full LUCID pipeline using a small detection rule dataset
sample (processing the full rule dataset can take several hours).

```bash
# 1. Clone the repository
git clone https://github.com/cisco-foundation-ai/detection-rule-classifier
cd detection-rule-classifier

# 1.5 [Recommended] Use a Python virtual environment
python -m venv .venv && source .venv/bin/activate && \
  pip install --upgrade pip

# 2. Install dependencies (for all stages)
pip install -e '.[classification,viz]'

# 3. Set your OpenAI API key (used for classification and insights)
export OPENAI_API_KEY="your-key-here"

# 4. Run the complete pipeline

# a. Fetch the detection rules.
# This command fetches only 80 rules, to speed up the classification
# step. To fetch the full default rule set of ~600 rules, omit the
# --max-rules flag.
python -m rules_fetcher.rules_fetcher --max-rules 80

# b. Classify the detection rules with MITRE ATT&CK techniques.
# Classification can take ~30 sec per rule, so be patient...
# By default, this automatically merges existing MITRE labels from
# the original rules.
# If you run into SSL errors, consider adding the flag
# --disable-ssl-verify.
python -m classification.pipeline

# c. Generate aggregated stats from the classification data.
python -m aggregation.pipeline \
  --config aggregation/config_aggregation.json

# d. Generate LLM-based insights from the aggregated data.
# If you run into SSL errors, consider adding the flag
# --disable-ssl-verify.
python -m aggregation.insights_generator \
  --config aggregation/config_insights.json

# e. Run the visualization app to view the data - it should open in
# a new browser window.
python -m streamlit run visualization/app.py
```

## Usage Instructions

### Prerequisites

- **Python**: Version 3.10 or higher
- **OpenAI API Key**: Required for AI-powered classification and insight
  generation
- **Hugging Face API Key**: For doing classification using models hosted
  on Hugging Face, as an alternative to OpenAI models

### Setup

Clone the repository:

```sh
git clone https://github.com/cisco-foundation-ai/detection-rule-classifier
cd detection-rule-classifier
```

[Optional, yet recommended] Use a Python virtual environment

```sh
python -m venv venv
source venv/bin/activate
```

Install dependencies (several options to choose from)

```sh
# Option 1: For all steps
pip install -e '.[all]'

# Option 2: Visualization only (lightweight, ~200 MB)
pip install -e '.[viz]'

# Option 3: Classification only (LLM/ML dependencies)
pip install -e '.[classification]'

# Option 4: For dev and testing
pip install -e '.[dev]'
```

Set up API keys (only needed for classification and insight generation):

```sh
export OPENAI_API_KEY="your-key-here"
export HUGGINGFACE_KEY="your-hf-key-here"  # Optional
```

### Fetch Detection Rules

Retrieve detection rules from a repository (defaults to
[this Splunk detection rule repository](https://github.com/splunk/security_content))
and prepares them for classification (removes any existing technique tags
so as not to bias the model).

```sh
python -m rules_fetcher.rules_fetcher
```

**Output:** Processed rules are saved to `output/rules/untagged/`

Notes:

- Add the `--help` flag to see supported options.
- If you want to fetch your own private rule set, you will probably want to
  modify or replace this code module.

### Classify Rules with MITRE ATT&CK techniques

Classify the fetched rules using AI-powered techniques mapping. By default,
this **automatically merges existing MITRE labels** from your original rules
with the AI classifier's predictions.

```sh
python -m classification.pipeline
```

Notes:

- The default configuration uses a two-step classification process for
  better accuracy (`--config classification/config_example_two_step.json`).
  The two-step approach first identifies plausible techniques, then
  refines to the most relevant ones, reducing false positives.
- Use `--config classification/config_example_one_step.json` for a faster
  single-step classification process.
- **Original merging**: By default, the pipeline merges existing MITRE
  labels from `output/rules/original/` with classifier predictions. Use
  `--no-merge-existing-labels` to disable this behavior.
- If you run into SSL errors, consider adding the
  `--disable-ssl-verify` flag, but use with caution.
- Check the source code of `classification/pipeline.py` for details on
  how to use models served from Hugging Face instead of OpenAI models.
- Add the `--help` flag to see more options.

**Output:** Classification results (with merged original labels if available)
are saved to `output/classification/classified_output.json`

### Generate aggregate stats

This step pre-computes all data transformations and statistical
aggregations, which are later used in the visualization app.

```sh
python -m aggregation.pipeline \
  --config aggregation/config_aggregation.json
```

**What this does:**

- Enriches techniques with MITRE ATT&CK metadata
- Joins technique, tactic and kill-chain mapping data
- Computes coverage statistics and trending analysis
- Creates data structures optimized for visualization

**Output:** Aggregated data saved to `output/aggregation/aggregated_data.json`

### Generate insights

Generate AI-powered insights from the aggregated data, using OpenAI
GPT-4o.

```sh
python -m aggregation.insights_generator \
  --config aggregation/config_insights.json
```

**Output:** Insights saved to `output/aggregation/insights.json`

If you run into SSL errors, consider adding the `--disable-ssl-verify`
flag, but use with caution.

### Original Label Merging

By default, the AI classifier's label predictions are merged with your
detection rules' existing MITRE ATT&CK labels, if they exist.
This makes your label data more complete, as some classification decisions
are ambiguous.

To **disable automatic merging** (and use the AI classifier's predictions only),
add this flag:

```sh
python -m classification.pipeline --no-merge-existing-labels
```

See [classification/README.md](classification/README.md) for detailed
instructions, format requirements, and advanced options.

### Visualize results

Launch the interactive Streamlit dashboard to explore classified rules:

```sh
python -m streamlit run visualization/app.py
```

Notes:

- If you just run the command above without doing the previous steps,
  the app will fall back to use pre-populated demo data from
  `aggregation/demo/`.
- Add the `--help` flag or check the source code for more options.

## Roadmap

See the
[open issues](https://github.com/cisco-foundation-ai/detection-rule-classifier/issues)
for a list of proposed features (and known issues).

## Contributing

Contributions are what make the open source community such an amazing
place to learn, inspire, and create. Any contributions you make are
**greatly appreciated**. For detailed contributing guidelines, please
see [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Distributed under the `Apache-2.0` License. See [LICENSE](LICENSE) for more
information.

## Contact

Foundation AI - <foundation-ai-oss@cisco.com>

Project Link:
[https://github.com/cisco-foundation-ai/detection-rule-classifier](https://github.com/cisco-foundation-ai/detection-rule-classifier)

## Acknowledgements

This template was adapted from
[https://github.com/othneildrew/Best-README-Template](https://github.com/othneildrew/Best-README-Template).
