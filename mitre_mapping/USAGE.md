# MITRE ATT&CK Mapper - Usage Guide

A Python library for mapping MITRE ATT&CK techniques to tactics and
sub-techniques.

## Installation

Install the required dependencies:

```bash
pip install -e .
```

**Dependencies:**

- `mitreattack-python`: For fetching MITRE ATT&CK data
- `psutil`: For memory usage monitoring and debugging

## Cache Persistence

The mapper automatically caches data locally to improve performance:

- **First run**:
  - Downloads the latest MITRE ATT&CK STIX data from GitHub
  - Processes and saves to `mitre_attack_cache.json`
  - Takes ~10-20 seconds depending on network speed
- **Subsequent runs**: Loads data from the cache file instantly
  (< 1 second)
- **Custom cache location**: You can specify a custom cache file path
- **Force refresh**: You can manually refresh the cache to get the
  latest data from MITRE

## Quick Start

### Basic Usage

```python
from mitre_attack_mapper import get_technique, get_techniques, get_sub_technique, get_sub_techniques

# Get a single technique
technique = get_technique("T1548")
print(f"Technique: {technique.name}")
print(f"Tactics: {', '.join([t.name for t in technique.tactics])}")
print(f"Sub-techniques: {len(technique.sub_techniques)}")

# Get multiple techniques
techniques = get_techniques(["T1548", "T1134", "T1059"])
for tech in techniques:
    tactics_str = ', '.join([t.name for t in tech.tactics])
    print(f"{tech.name} -> {tactics_str}")

# Get a single sub-technique
sub_technique = get_sub_technique("T1548.001")
print(f"Sub-technique: {sub_technique.name}")
print(f"Parent: {sub_technique.technique.name}")

# Get multiple sub-techniques
sub_techniques = get_sub_techniques(["T1548.001", "T1548.002"])
for sub in sub_techniques:
    print(f"{sub.name} -> {sub.technique.name}")
```

### Using the Mapper Class

```python
from mitre_attack_mapper import MitreAttackMapper

# Create a mapper instance (uses default version 'master')
mapper = MitreAttackMapper()

# Or specify a specific version
mapper = MitreAttackMapper(version="ATT&CK-v15.1")

# Use the same methods
technique = mapper.get_technique("T1059")

# Explore relationships - techniques can belong to multiple tactics
print(f"Technique: {technique.name}")
print(f"Tactics: {', '.join([t.name for t in technique.tactics])}")

# Explore a specific tactic
if technique.tactics:
    tactic = technique.tactics[0]
    print(f"Tactic: {tactic.name}")
    print(f"Techniques in this tactic: {len(tactic.techniques)}")

# Explore sub-techniques
for sub in technique.sub_techniques:
    print(f"  {sub.name} ({sub.id})")
```

### Using Custom Cache Location

```python
from mitre_attack_mapper import MitreAttackMapper

# Specify a custom cache file location
mapper = MitreAttackMapper(
    cache_file="/path/to/my/custom_cache.json"
)

# Use normally
technique = mapper.get_technique("T1548")
```

### Using Specific ATT&CK Versions

```python
from mitre_attack_mapper import MitreAttackMapper

# Use the latest version from master branch (default)
mapper_latest = MitreAttackMapper(version="master")

# Use a specific stable version (recommended for production)
mapper_v15 = MitreAttackMapper(version="ATT&CK-v15.1")
mapper_v14 = MitreAttackMapper(version="ATT&CK-v14.1")

# Version is included in the STIX filename, so you can have
# multiple versions
# enterprise-attack-master.json
# enterprise-attack-ATTandCK-v15.1.json
# enterprise-attack-ATTandCK-v14.1.json
```

**Version Options:**

- `"master"` (default): Latest version, may change at any time
- `"ATT&CK-v15.1"`: Stable version 15.1
- `"ATT&CK-v14.1"`: Stable version 14.1
- Any valid branch/tag from
  [MITRE's CTI repository](https://github.com/mitre/cti)

**When to Use Each:**

- **Development**: `"master"` for latest features
- **Production**: Specific version like `"ATT&CK-v15.1"` for stability
- **Testing**: Multiple versions to compare changes

### Refreshing the Cache

```python
from mitre_attack_mapper import MitreAttackMapper

# Create mapper
mapper = MitreAttackMapper()

# Force refresh from MITRE ATT&CK (updates cache file)
mapper.refresh_cache()
```

### Checking Cache Status

```python
from mitre_attack_mapper import MitreAttackMapper
import os

mapper = MitreAttackMapper()

# Check if cache exists
if mapper.cache_file.exists():
    print(f"Cache exists at: {mapper.cache_file}")
    size_mb = os.path.getsize(mapper.cache_file) / (1024 * 1024)
    print(f"Cache size: {size_mb:.2f} MB")
```

### Using Cyber Kill Chain Mappings

```python
from mitre_attack_mapper import MitreAttackMapper

mapper = MitreAttackMapper()

# Get a technique and explore its kill chain stages
technique = mapper.get_technique("T1566")  # Phishing
if technique and technique.tactics:
    tactic = technique.tactics[0]  # Initial Access
    print(f"Tactic: {tactic.name}")

    # Show kill chain stages for this tactic
    for stage in tactic.kill_chain_stages:
        print(f"  Kill Chain Stage: {stage.name}")
        print(f"  Description: {stage.description}")

# Explore a specific kill chain stage
exploitation_stage = mapper._kill_chain_stages.get('exploitation')
if exploitation_stage:
    print(f"\nStage: {exploitation_stage.name}")
    print(f"Associated Tactics:")
    for tactic in exploitation_stage.tactics:
        print(f"  - {tactic.name}")
```

**Example Output:**

```text
Tactic: Initial Access
  Kill Chain Stage: Delivery
  Description: Transmitting the weapon to the target environment
  Kill Chain Stage: Exploitation
  Description: Exploiting vulnerabilities to execute code on target
               system

Stage: Exploitation
Associated Tactics:
  - Initial Access
  - Execution
```

## Data Classes

### CyberKillChainStage

Represents a Cyber Kill Chain Stage.

- `id`: str - Stage identifier (e.g., "reconnaissance",
  "exploitation")
- `name`: str - Stage name (e.g., "Reconnaissance", "Exploitation")
- `description`: str - Description of the stage
- `tactics`: List[Tactic] - List of MITRE ATT&CK tactics mapped to
  this stage

**Kill Chain Stages:**

1. **Reconnaissance**: Gathering information to plan future operations
2. **Weaponization**: Creating or preparing exploit code and payloads
3. **Delivery**: Transmitting the weapon to the target environment
4. **Exploitation**: Exploiting vulnerabilities to execute code on
   target system
5. **Installation**: Installing malware or maintaining access on the
   target system
6. **Command and Control**: Establishing command and control channel
   for remote manipulation
7. **Actions on Objectives**: Taking actions to achieve the intended
   objectives (data theft, destruction, etc.)

### Tactic

Represents a MITRE ATT&CK Tactic (e.g., Initial Access, Execution).

- `name`: str - The name of the tactic
- `id`: str - The tactic ID (e.g., "TA0001")
- `techniques`: List[Technique] - List of techniques in this tactic
- `kill_chain_stages`: List[CyberKillChainStage] - List of Cyber Kill
  Chain stages this tactic maps to

### Technique

Represents a MITRE ATT&CK Technique.

- `name`: str - The name of the technique
- `id`: str - The technique ID (e.g., "T1548")
- `tactics`: List[Tactic] - List of tactics this technique belongs to
  (a technique can belong to multiple tactics)
- `sub_techniques`: List[SubTechnique] - List of sub-techniques

### SubTechnique

Represents a MITRE ATT&CK Sub-Technique.

- `name`: str - The name of the sub-technique
- `id`: str - The sub-technique ID (e.g., "T1548.001")
- `technique`: Technique - The parent technique

## API Reference

### Functions

#### `get_technique(technique_id: str) -> Optional[Technique]`

Get a technique by its ID.

**Parameters:**

- `technique_id`: The technique ID (e.g., "T1548")

**Returns:**

- Technique object if found, None otherwise

#### `get_techniques(technique_ids: List[str]) -> List[Technique]`

Get multiple techniques by their IDs.

**Parameters:**

- `technique_ids`: List of technique IDs

**Returns:**

- List of Technique objects (skips any not found)

#### `get_sub_technique(sub_technique_id: str) -> Optional[SubTechnique]`

Get a sub-technique by its ID.

**Parameters:**

- `sub_technique_id`: The sub-technique ID (e.g., "T1548.001")

**Returns:**

- SubTechnique object if found, None otherwise

#### `get_sub_techniques(sub_technique_ids: List[str]) -> List[SubTechnique]`

Get multiple sub-techniques by their IDs.

**Parameters:**

- `sub_technique_ids`: List of sub-technique IDs

**Returns:**

- List of SubTechnique objects (skips any not found)

## Example

Run the included examples:

```bash
# Basic usage examples
python example_usage.py

# Memory monitoring test
python test_memory.py
```

**example_usage.py** demonstrates:

- Getting single and multiple techniques
- Getting single and multiple sub-techniques
- Exploring relationships between tactics, techniques, and
  sub-techniques

**test_memory.py** demonstrates:

- Memory usage monitoring during initialization
- Helps identify potential memory issues

### `MitreAttackMapper(cache_file: Optional[str] = None, version: Optional[str] = None)`

Create a new mapper instance.

**Parameters:**

- `cache_file`: Optional path to JSON cache file. Defaults to
  `mitre_attack_cache.json` in the module directory.
- `version`: Optional MITRE ATT&CK version to use. Defaults to
  `"master"` (latest).
  - Examples: `"master"`, `"ATT&CK-v15.1"`, `"ATT&CK-v14.1"`
  - Must be a valid branch or tag from
    [MITRE's CTI repository](https://github.com/mitre/cti)

**Methods:**

- `get_technique(technique_id: str)`: Get a technique by ID
- `get_techniques(technique_ids: List[str])`: Get multiple techniques
- `get_sub_technique(sub_technique_id: str)`: Get a sub-technique by
  ID
- `get_sub_techniques(sub_technique_ids: List[str])`: Get multiple
  sub-techniques
- `refresh_cache()`: Force refresh the cache from MITRE ATT&CK

**Attributes:**

- `version`: The ATT&CK version being used
- `cache_file`: Path to the cache file
- `stix_file`: Path to the STIX data file (includes version in
  filename)

## Debugging and Memory Monitoring

The library includes comprehensive logging and memory monitoring to
help identify performance issues:

### Logging

All operations are logged with timestamps and memory usage information:

```python
import logging

# Enable INFO level logging to see progress
logging.basicConfig(level=logging.INFO)

from mitre_attack_mapper import MitreAttackMapper

mapper = MitreAttackMapper()
```

This will show:

- Download progress and file sizes
- Memory usage at each stage
- Number of items loaded (tactics, techniques, sub-techniques)
- Cache operations

### Memory Monitoring

The library automatically tracks memory usage at key points:

```python
from mitre_attack_mapper import MitreAttackMapper, log_memory_usage

# Manual memory check
log_memory_usage("Before mapper creation")
mapper = MitreAttackMapper()
log_memory_usage("After mapper creation")
```

### Memory Optimization

The library includes several optimizations to prevent memory leaks:

1. **STIX data cleanup**: Raw STIX data is cleared from memory after
   processing
2. **Garbage collection**: Explicit garbage collection after large
   operations
3. **Efficient caching**: Only essential data is stored in memory
4. **Minimal circular references**: Data structures are designed to
   minimize reference cycles

### Troubleshooting

If you experience memory issues:

1. **Monitor memory usage**: Run `python test_memory.py` to see
   detailed memory tracking
2. **Check logs**: Look for abnormal memory jumps in the logs
3. **Use the cache**: After first run, subsequent loads use minimal
   memory
4. **Clear cache**: Delete cache files to force a fresh download and
   rebuild

## Notes

- The library uses the `mitreattack-python` package to fetch the
  latest MITRE ATT&CK data
- **Cache Behavior**:
  - On first run, downloads STIX data from GitHub and processes it
    (takes ~10-20 seconds)
  - On subsequent runs, loads from cache instantly (< 1 second)
  - Cache file is stored in JSON format for easy inspection
- **Files Created**:
  - `enterprise-attack.json`: Raw STIX data from MITRE (~10 MB)
  - `mitre_attack_cache.json`: Processed cache (~1-2 MB)
  - Both files are automatically managed and can be safely deleted to
    force a refresh
- The library automatically filters out revoked and deprecated
  techniques
- **Multiple Tactics**: A technique can belong to multiple tactics.
  The `Technique` class has a `tactics` list that contains all
  associated tactics
- Default cache location: `<module_dir>/mitre_attack_cache.json`
- **Memory Usage**: Typical memory usage is 50-150 MB during
  initialization, 20-50 MB after cleanup
