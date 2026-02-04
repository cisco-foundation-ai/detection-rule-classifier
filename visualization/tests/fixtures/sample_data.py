# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Sample MITRE ATT&CK data for testing."""

from mitre_mapping.mitre_attack_mapper import (
    CyberKillChainStage,
    SubTechnique,
    Tactic,
    Technique,
)

# ===== Cyber Kill Chain Stages =====

KILL_CHAIN_EXPLOITATION = CyberKillChainStage(
    id="exploitation",
    name="Exploitation",
    description="Exploiting vulnerabilities to gain initial access",
    kill_chain_step_number=4,
    tactics=[],  # Will be populated below
)

KILL_CHAIN_INSTALLATION = CyberKillChainStage(
    id="installation",
    name="Installation",
    description="Installing malware or persistence mechanisms",
    kill_chain_step_number=5,
    tactics=[],  # Will be populated below
)

KILL_CHAIN_ACTIONS = CyberKillChainStage(
    id="actions_on_objectives",
    name="Actions on Objectives",
    description="Achieving the final objective",
    kill_chain_step_number=7,
    tactics=[],  # Will be populated below
)


# ===== Tactics =====

TACTIC_EXECUTION = Tactic(
    name="Execution",
    description="Execute code on target system",
    id="TA0002",
    url="https://attack.mitre.org/tactics/TA0002/",
    techniques=[],  # Will be populated below
    kill_chain_stages=[KILL_CHAIN_EXPLOITATION],
)

TACTIC_PERSISTENCE = Tactic(
    name="Persistence",
    description="Maintain foothold in the system",
    id="TA0003",
    url="https://attack.mitre.org/tactics/TA0003/",
    techniques=[],  # Will be populated below
    kill_chain_stages=[KILL_CHAIN_INSTALLATION],
)

TACTIC_DEFENSE_EVASION = Tactic(
    name="Defense Evasion",
    description="Avoid detection",
    id="TA0005",
    url="https://attack.mitre.org/tactics/TA0005/",
    techniques=[],  # Will be populated below
    kill_chain_stages=[KILL_CHAIN_EXPLOITATION],
)

TACTIC_CREDENTIAL_ACCESS = Tactic(
    name="Credential Access",
    description="Steal credentials",
    id="TA0006",
    url="https://attack.mitre.org/tactics/TA0006/",
    techniques=[],  # Will be populated below
    kill_chain_stages=[KILL_CHAIN_ACTIONS],
)


# Update kill chain stages with tactics
KILL_CHAIN_EXPLOITATION.tactics = [TACTIC_EXECUTION, TACTIC_DEFENSE_EVASION]
KILL_CHAIN_INSTALLATION.tactics = [TACTIC_PERSISTENCE]
KILL_CHAIN_ACTIONS.tactics = [TACTIC_CREDENTIAL_ACCESS]


# ===== Techniques =====

TECHNIQUE_T1059 = Technique(
    name="Command and Scripting Interpreter",
    id="T1059",
    description="Adversaries may abuse command and script interpreters",
    url="https://attack.mitre.org/techniques/T1059/",
    tactics=[TACTIC_EXECUTION],
    sub_techniques=[],  # Will be populated below
)

TECHNIQUE_T1027 = Technique(
    name="Obfuscated Files or Information",
    id="T1027",
    description="Adversaries may obfuscate files or information to evade detection",
    url="https://attack.mitre.org/techniques/T1027/",
    tactics=[TACTIC_DEFENSE_EVASION],
    sub_techniques=[],
)

TECHNIQUE_T1558 = Technique(
    name="Steal or Forge Kerberos Tickets",
    id="T1558",
    description="Adversaries may steal or forge Kerberos tickets",
    url="https://attack.mitre.org/techniques/T1558/",
    tactics=[TACTIC_CREDENTIAL_ACCESS],
    sub_techniques=[],  # Will be populated below
)

TECHNIQUE_T1098 = Technique(
    name="Account Manipulation",
    id="T1098",
    description="Adversaries may manipulate accounts to maintain access",
    url="https://attack.mitre.org/techniques/T1098/",
    tactics=[TACTIC_PERSISTENCE],
    sub_techniques=[],  # Will be populated below
)


# Add techniques to tactics
TACTIC_EXECUTION.techniques = [TECHNIQUE_T1059]
TACTIC_DEFENSE_EVASION.techniques = [TECHNIQUE_T1027]
TACTIC_CREDENTIAL_ACCESS.techniques = [TECHNIQUE_T1558]
TACTIC_PERSISTENCE.techniques = [TECHNIQUE_T1098]


# ===== Sub-Techniques =====

SUB_TECHNIQUE_T1059_001 = SubTechnique(
    name="PowerShell",
    id="T1059.001",
    description="Adversaries may abuse PowerShell commands and scripts",
    url="https://attack.mitre.org/techniques/T1059/001/",
    technique=TECHNIQUE_T1059,
)

SUB_TECHNIQUE_T1558_003 = SubTechnique(
    name="Kerberoasting",
    id="T1558.003",
    description="Adversaries may abuse Kerberos ticket requests to obtain credentials",
    url="https://attack.mitre.org/techniques/T1558/003/",
    technique=TECHNIQUE_T1558,
)

SUB_TECHNIQUE_T1098_001 = SubTechnique(
    name="Additional Cloud Credentials",
    id="T1098.001",
    description="Adversaries may add credentials to cloud accounts",
    url="https://attack.mitre.org/techniques/T1098/001/",
    technique=TECHNIQUE_T1098,
)


# Add sub-techniques to techniques
TECHNIQUE_T1059.sub_techniques = [SUB_TECHNIQUE_T1059_001]
TECHNIQUE_T1558.sub_techniques = [SUB_TECHNIQUE_T1558_003]
TECHNIQUE_T1098.sub_techniques = [SUB_TECHNIQUE_T1098_001]


# ===== Helper Functions =====


def get_mock_technique_by_id(technique_id: str):
    """Return mock technique by ID."""
    technique_map = {
        "T1059": TECHNIQUE_T1059,
        "T1027": TECHNIQUE_T1027,
        "T1558": TECHNIQUE_T1558,
        "T1098": TECHNIQUE_T1098,
    }
    return technique_map.get(technique_id)


def get_mock_sub_technique_by_id(sub_technique_id: str):
    """Return mock sub-technique by ID."""
    sub_technique_map = {
        "T1059.001": SUB_TECHNIQUE_T1059_001,
        "T1558.003": SUB_TECHNIQUE_T1558_003,
        "T1098.001": SUB_TECHNIQUE_T1098_001,
    }
    return sub_technique_map.get(sub_technique_id)


# ===== Sample Classification Data =====

SAMPLE_CLASSIFICATION_DATA = [
    {
        "id": "test_rule_1.yml",
        "relevant_techniques": ["T1059.001", "T1027"],
    },
    {
        "id": "test_rule_2.yml",
        "relevant_techniques": ["T1558.003"],
    },
    {
        "id": "test_rule_3.yml",
        "relevant_techniques": ["T1059", "T1098.001"],
    },
    {
        "id": "test_rule_4.yml",
        "relevant_techniques": ["T1027", "T1098"],
    },
]
