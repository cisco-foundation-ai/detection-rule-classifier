# Classification Usage Notes

## Original Label Merging

The classification pipeline **automatically merges existing MITRE ATT&CK
labels** from your original detection rules with the AI classifier's
predictions. This ensures comprehensive coverage by combining techniques
from both sources, preserving human-curated labels while adding
AI-discovered techniques.

### How It Works

By default, the classification pipeline:

1. Runs AI classification on the detection rules
2. Looks for the original rule files in `output/rules/original/`
3. Extracts existing MITRE technique IDs from the original files
4. Merges them with the classifier's predictions using set union
5. Outputs a single file with both AI predictions and original labels

This means you get the best of both worlds: human expertise combined
with AI-powered discovery of additional relevant techniques.

### Controlling Merge Behavior

**Default behavior** (merge enabled):

```bash
python -m classification.pipeline
```

**Disable merging** (classifier predictions only):

```bash
python -m classification.pipeline --no-merge-existing-labels
```

**Custom path to original rules:**

```bash
python -m classification.pipeline --original-rules-folder /path/to/original/rules
```

### Output

The pipeline outputs classification results to
`output/classification/classified_output.json`.

**When merging is enabled** (default):

- An intermediate file `unmerged_classified_output.json` is created with
  classifier-only predictions
- The final `classified_output.json` contains merged results (AI +
  original labels)

**When merging is disabled** (`--no-merge-existing-labels`):

- Only `classified_output.json` is created with classifier-only
  predictions
- No intermediate file is generated

The final output contains:

- **Classifier predictions**: AI-identified MITRE techniques
- **Original labels** (if found and merge enabled): Human-curated MITRE
  techniques from original rules
- **Merged results**: Union of both sets, with duplicates removed

**Example output format:**

```json
[
  {
    "id": "rule_id_1",
    "plausible_techniques": ["T1059", "T1105", "T1566"],
    "relevant_techniques": ["T1059", "T1105", "T1003"]
  }
]
```

In this example, if the classifier predicted `["T1059", "T1105"]` and
the original rule had `["T1003", "T1059"]`, the merged result is
`["T1003", "T1059", "T1105"]` (the union of both sets, sorted and
deduplicated).

### When Merging Happens

The pipeline attempts to merge original labels if:

1. The `--merge-existing-labels` flag is `True` (default)
2. The original rules folder exists (default: `output/rules/original/`)
3. Original rule files can be found and parsed

If any of these conditions are not met, the pipeline logs an
informational message and continues with classifier predictions only.

### Important Considerations

**Format Compatibility:**

This feature is designed specifically for **Splunk security content
YAML format**, which stores MITRE technique IDs in the
`tags.mitre_attack_id` field.

**Example Splunk rule structure:**

```yaml
name: Suspicious Process Execution
tags:
  mitre_attack_id:
    - T1059.001
    - T1003.001
```

**Other Rule Formats:**

If you're using a different rule format (e.g., Sigma rules, Elastic
rules), you'll need to modify the parsing logic in the
`extract_mitre_ids_from_yaml_rule()` function in
`classification/merge_original_labels.py` to match your format's
structure.

**When to Disable Merging:**

- Your rules don't have existing MITRE labels
- You want to evaluate classifier performance independently from
  original
- You're using a rule format that isn't compatible with the current
  parser
- You're doing a pure AI-classification experiment

## Standalone Merge Tool

The `classification/merge_original_labels.py` script is still available
as a standalone tool for advanced use cases:

**Merge existing classification output with original:**

```bash
python -m classification.merge_original_labels \
  --classifier-output output/classification/classified_output.json \
  --original-rules-folder output/rules/original \
  --output output/classification/classified_output_merged.json
```

This can be useful if you:

- Need to re-merge original after the fact
- Want to create separate output files for comparison
- Are working with classification results from a different source

**Options:**

- `--debug`: Enable detailed debug logging to see the merge process in
  action

## Additional Pipeline Options

The classification pipeline supports many other options:

```bash
python -m classification.pipeline --help
```

Key options include:

- `--config`: Specify configuration file (default: two-step
  classification)
- `--input-path`: Path to detection rules (default:
  `output/rules/untagged`)
- `--output-file-path`: Where to save results (default:
  `output/classification/classified_output.json`)
- `--max-rules-to-process`: Limit number of rules for testing
- `--num-workers`: Parallel workers for API calls
- `--retries`: Retry attempts for failed API calls
- `--disable-ssl-verify`: Bypass SSL verification (use with caution)
- `--debug`: Enable debug logging
