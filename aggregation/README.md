# Aggregation & Insights Layer

This module provides data aggregation and AI-powered insights for detection
rules classification results.

## Overview

The aggregation layer sits between classification and visualization,
pre-computing all data transformations and statistical analysis. This design:

- **Separates concerns**: Data processing separate from visualization
- **Improves performance**: Visualization loads instantly with pre-computed data
- **Enables insights**: LLM-powered analysis of coverage patterns
- **Maintains correctness**: Produces identical results to original
  implementation

## Architecture

```text
Classification → Aggregation Pipeline → aggregated_data.json → Visualization
                                              ↓ (optional)
                                       Insights Generator → insights.json → Visualization
```

## Components

### 1. Data Processor (`data_processor.py`)

Core data transformation logic:

- Loads classified rules from JSON
- Enriches with MITRE ATT&CK metadata
- Explodes techniques, tactics, and kill-chain mappings
- Computes statistical aggregations

### 2. Aggregation Pipeline (`pipeline.py`)

Orchestrates data processing:

- NO LLM calls (pure data transformation)
- Saves aggregated data to JSON
- Provides CLI interface

**Usage:**

```bash
python -m aggregation.pipeline \
  --config aggregation/config_aggregation.json \
  --input-file output/classification/classified_output.json \
  --output-dir output/aggregation
```

### 3. Prompts Module (`prompts.py`)

Hardcoded LLM prompt templates for:

- Coverage gap analysis
- Recommendations
- Trends analysis
- Anomaly detection

### 4. Insights Generator (`insights_generator.py`)

Standalone tool for generating LLM-powered insights:

- Runs independently after aggregation
- Can be executed anytime
- Currently produces empty structure (LLM integration coming in future phases)

**Usage:**

```bash
python -m aggregation.insights_generator \
  --config aggregation/config_insights.json \
  --input-file output/aggregation/aggregated_data.json \
  --output-file output/aggregation/insights.json
```

## Configuration Files

### `config_aggregation.json`

Configuration for aggregation pipeline:

```json
{
  "input": {
    "classified_output": "output/classification/classified_output.json"
  },
  "output": {
    "aggregated_data": "output/aggregation/aggregated_data.json",
    "save_config_snapshot": true,
    "pretty_print": true
  },
  "processing": {
    "trending_techniques_source": "visualization/data/trending_techniques.csv"
  }
}
```

### `config_insights.json`

Configuration for insights generator:

```json
{
  "llm": {
    "provider": "openai",
    "model": "gpt-4o",
    "temperature": 0.7,
    "max_tokens": 2000
  },
  "insights": {
    "enabled_types": [
      "coverage_gaps",
      "recommendations",
      "trends_analysis",
      "anomalies"
    ],
    "coverage_gap_threshold": 5,
    "trending_techniques_source": "visualization/data/trending_techniques.csv"
  },
  "output": {
    "pretty_print": true
  }
}
```

## Output Format

### Aggregated Data (`aggregated_data.json`)

```json
{
  "metadata": {
    "total_rules": 100,
    "total_techniques": 250,
    "total_tactics": 14,
    "total_kill_chains": 7,
    "generated_at": "2026-01-14T..."
  },
  "aggregations": {
    "technique_counts": [...],
    "tactic_coverage": [...],
    "kill_chain_coverage": [...],
    "tactic_killchain_matrix": [...],
    "trending_analysis": [...]
  },
  "dataframes": {
    "rules_summary": [...],
    "rule_techniques": [...],
    "rule_tactics": [...],
    "rule_techniques_raw": [...],
    "rule_tactics_raw": [...],
    "rule_kill_chains_raw": [...]
  }
}
```

### Insights Data (`insights.json`)

```json
{
  "insights": {
    "coverage_gaps": {
      "summary": "...",
      "details": [...]
    },
    "recommendations": [...],
    "trends_analysis": {...},
    "anomalies": {...}
  },
  "generated_at": "2026-01-14T...",
  "llm_config": {...},
  "metadata": {
    "enabled_types": [...],
    "coverage_gap_threshold": 5,
    "implementation_status": "empty_structure"
  }
}
```

## Demo Data

For quick exploration without running the full pipeline, demo data is available
in `aggregation/demo/`:

- `aggregated_data.json` - Sample aggregated detection rules
- `insights.json` - Sample AI-generated insights
- `config.json` - Configuration snapshot

The visualization app automatically falls back to this demo data when no
user-generated data exists in `output/aggregation/`. This allows you to:

- Explore the visualization immediately after installation
- Understand the expected data format
- Test the app without API keys or classification runs

**To use demo data:**

```bash
streamlit run visualization/app.py
```

The app will display a notice when showing demo data and guide you to generate
your own.

## Complete Workflow

```bash
# 1. Fetch rules
python -m rules_fetcher.rules_fetcher

# 2. Classify rules
python -m classification.pipeline \
  --config classification/config_example_one_step.json

# 3. Aggregate data (NEW)
python -m aggregation.pipeline \
  --config aggregation/config_aggregation.json

# 4. Generate insights (OPTIONAL)
python -m aggregation.insights_generator \
  --config aggregation/config_insights.json

# 5. Visualize
streamlit run visualization/app.py -- \
  --classified-output-file-path output/aggregation/aggregated_data.json
```

## Visualization Updates

The visualization layer now:

- Automatically detects aggregated vs. classified data format
- Loads pre-computed data when available
- Falls back to traditional processing for backward compatibility
- Displays insights dashboard when `insights.json` is available
- Shows identical results to original implementation

## Testing

Run tests for aggregation components:

```bash
# Run all tests
pytest aggregation/tests/

# Run specific test files
pytest aggregation/tests/test_data_processor.py
pytest aggregation/tests/test_pipeline.py
pytest aggregation/tests/test_prompts.py
pytest aggregation/tests/test_insights_generator.py
```

## Enhanced Insights Features (✅ Complete)

### Executive Summary

**Strategic overview at the top of the dashboard** with:

- **Critical Gaps**: Top 3-5 coverage gaps with highest risk
- **Priority Actions**: Up to 5 actionable recommendations ranked by impact

**Design**: Executive summary synthesizes per-visualization insights (Option 2
architecture)

### Per-Visualization Insights

**Contextual analysis below each chart** including:

- **Interpretation**: What this visualization shows
- **Key Findings**: 2-3 specific observations with data points
- **Recommendations**: 1-3 actionable items for this view
- **Anomalies**: Unusual patterns detected (if any)

### Execution Order

1. **Step 1**: Generate per-visualization insights (5 charts analyzed)
2. **Step 2**: Generate executive summary using viz insights as context
3. Result: Cohesive narrative from detailed → strategic

## Prompt Engineering Best Practices

### For Highest Quality LLM Outputs

#### 1. Structure & Format

✅ **Use JSON schema** - Include exact structure in prompt  
✅ **Show examples** - Demonstrate desired output format  
✅ **Specify limits** - "Top 3-5" not "several"  
✅ **Request reasoning** - Ask for brief rationale

#### 2. Context & Grounding

✅ **Include full data** - Pass relevant aggregated metrics  
✅ **Provide domain context** - Explain MITRE ATT&CK, kill chains  
✅ **Reference actual values** - "23 rules" not "some rules"  
✅ **Comparative baseline** - What's expected vs. observed

#### 3. Output Quality

✅ **Specificity requirement** - "Avoid generic advice"  
✅ **Actionability focus** - "Create detection for X" not "improve coverage"  
✅ **Validation instructions** - "Return ONLY valid JSON"  
✅ **Constraint enforcement** - Repeat limits multiple times

#### 4. LLM Configuration

```json
{
  "model": "gpt-4o",
  "temperature": 0.3,
  "max_tokens": 3000,
  "response_format": { "type": "json_object" }
}
```

**Why these settings:**

- **gpt-4o**: Best reasoning capabilities
- **temperature: 0.3**: Lower for consistency and focus
- **max_tokens: 3000**: Enough for detailed structured output
- **json_object**: Forces valid JSON responses

#### 5. Response Parsing

- Parse JSON strictly with error handling
- Validate schema before saving
- Handle partial/invalid responses gracefully
- Log errors for debugging
- Provide fallback empty structure

### Prompt Architecture (Option 2)

**Executive Summary receives viz insights as context:**

```python
# 1. Generate viz insights first
viz_insights = generate_visualization_insights(aggregated_data, llm_config)

# 2. Generate executive summary WITH viz insights
exec_summary = generate_executive_summary(
    aggregated_data=aggregated_data,
    visualization_insights=viz_insights,  # Passed as context
    llm_config=llm_config
)
```

**Benefits:**

- Executive summary synthesizes detailed findings
- Avoids redundant analysis
- More cohesive narrative
- References specific visualization insights

## Implementation Phases

### Phase 1 (✅ Complete)

- Aggregation pipeline (no LLM)
- Refactored visualization to use aggregated data
- Correctness validated

### Phase 2 (✅ Complete)

- Prompts module
- Insights generator (empty output initially)
- Insights display in visualization

### Phase 3 (✅ Complete)

- Implemented LLM calls with OpenAI integration
- Executive summary + per-viz insights
- Option 2 architecture (viz insights → executive summary)
- Comprehensive prompt engineering
- Enhanced visualization UI with strategic insights

## Benefits

1. **Separation of Concerns**: Data processing separate from visualization
2. **Performance**: Visualization loads instantly with pre-computed data
3. **Correctness**: Explicit validation that behavior is preserved
4. **Extensibility**: Easy to add new aggregations without touching
   visualization
5. **Insights**: Optional LLM-powered analysis provides actionable intelligence
6. **Debugging**: Intermediate outputs make pipeline transparent
7. **Independent Execution**: Can run insights generator separately, anytime

## Future Enhancements

- Real LLM integration in insights generator
- Support for custom aggregation functions
- Real-time insight generation in visualization
- Comparison between multiple classification runs
- Export insights to PDF/HTML reports
- Batch insights generation for multiple datasets
