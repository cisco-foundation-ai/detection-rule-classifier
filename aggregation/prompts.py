# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
LLM Prompt Templates for Detection Rule Insights.

This module contains all prompt templates used by the insights generator to create
LLM-powered analysis of detection coverage. Prompts are stored as Python strings
rather than separate files for several key reasons:

Why Python Strings:
    - Easy variable substitution via .format() method
    - Type safety and validation at import time
    - Full IDE support (syntax highlighting, find/replace, refactoring)
    - Simple testing - prompts can be imported and validated in unit tests
    - No runtime file I/O or path management complexity
    - Clear git diffs showing exactly what changed

Prompt Structure:
    Each prompt template includes:
    - Context description for the LLM
    - Input data format expectations
    - Output format specification (usually JSON)
    - Examples of expected output
    - Guidelines and constraints

Available Prompts:
    - EXECUTIVE_SUMMARY_PROMPT: High-level strategic overview with gaps and actions
    - PER_VISUALIZATION_INSIGHTS_PROMPT: Chart-specific analysis and recommendations
    - COVERAGE_GAPS_PROMPT: Detailed gap analysis (legacy, may be deprecated)
    - RECOMMENDATIONS_PROMPT: Actionable recommendations (legacy, may be deprecated)
    - TRENDS_ANALYSIS_PROMPT: Trending technique analysis (legacy, may be deprecated)
    - ANOMALIES_PROMPT: Anomaly detection (legacy, may be deprecated)

Modifying Prompts:
    1. Edit the prompt string constant in this file
    2. Test with: pytest aggregation/tests/test_prompts.py
    3. Validate with real data: python -m aggregation.insights_generator --debug
    4. Review LLM output quality before committing changes

Variable Substitution:
    Prompts use Python's .format() method for variable insertion:
    - {aggregated_data}: JSON summary of detection statistics
    - {visualization_insights}: Pre-computed per-chart insights
    - {chart_type}, {chart_title}, etc.: Chart-specific metadata

    Important: Use double braces {{}} for literal braces in JSON examples

Example Usage:
    >>> from aggregation.prompts import get_prompt_template, format_prompt
    >>> template = get_prompt_template("executive_summary")
    >>> prompt = format_prompt("executive_summary", aggregated_data="{...}", ...)
"""

# Coverage Gaps Analysis Prompt
COVERAGE_GAPS_PROMPT = """
You are an expert cybersecurity detection engineer analyzing detection rule coverage against the MITRE ATT&CK framework.

Your task is to identify coverage gaps in tactics, techniques, and kill-chain stages based on the aggregated detection data provided below.

Context - Aggregated Detection Data:
{aggregated_data}

Analysis Parameters:
- Coverage gap threshold: {threshold} rules (tactics with fewer rules are considered gaps)

Task: Identify coverage gaps focusing on:
1. Tactics with fewer than {threshold} detection rules
2. Missing or under-represented kill-chain stages
3. High-priority trending techniques without sufficient coverage
4. Critical gaps that leave organizations vulnerable

Return your analysis as a JSON object with this EXACT structure:
{{
  "summary": "Brief 2-3 sentence overview of the most critical gaps",
  "details": [
    {{
      "type": "tactic_gap|technique_gap|killchain_gap",
      "name": "Name of the tactic/technique/kill-chain stage",
      "rule_count": <number of rules covering this>,
      "severity": "high|medium|low",
      "recommendation": "Specific actionable recommendation"
    }}
  ]
}}

Important:
- Focus on the most actionable gaps (limit to top 10)
- Prioritize high-severity gaps that represent significant vulnerabilities
- Provide specific, actionable recommendations
- Return ONLY valid JSON, no additional text
"""

# Recommendations Prompt
RECOMMENDATIONS_PROMPT = """
You are a security detection expert providing strategic recommendations for improving detection coverage.

Your task is to recommend priority techniques and tactics for creating new detection rules based on the analysis of current coverage.

Context - Aggregated Detection Data:
{aggregated_data}

Trending Techniques Data:
{trending_data}

Task: Provide prioritized recommendations considering:
1. Trending attack techniques with no or low coverage
2. Critical tactics needing more detection rules
3. High-impact techniques frequently used by threat actors
4. Techniques that would provide the best ROI for detection coverage

Return your recommendations as a JSON array with this EXACT structure:
[
  {{
    "rank": 1,
    "technique_id": "T1234" or "T1234.001",
    "technique_name": "Full technique name",
    "tactic": "Associated tactic name",
    "priority": "high|medium|low",
    "rationale": "2-3 sentence explanation of why this is important",
    "current_coverage": <number of existing rules>,
    "trending_rank": <position in trending techniques, or null>,
    "estimated_impact": "Brief description of impact if implemented"
  }}
]

Important:
- Provide top 15 recommendations maximum
- Rank by priority (most important first)
- Include both trending techniques and critical gaps
- Be specific and actionable
- Return ONLY valid JSON, no additional text
"""

# Trends Analysis Prompt
TRENDS_ANALYSIS_PROMPT = """
You are a security analyst comparing detection coverage against real-world trending attack patterns.

Your task is to analyze how well the current detection coverage aligns with trending attack techniques observed in actual incidents.

Context - Aggregated Detection Data:
{aggregated_data}

Trending Techniques Data (based on real incident data):
{trending_data}

Task: Compare coverage against trending patterns and identify:
1. Well-covered trending techniques (adequate detection)
2. Trending techniques with insufficient or no coverage (vulnerabilities)
3. Over-represented areas (possibly excessive focus)
4. Under-represented areas relative to threat landscape
5. Overall coverage alignment score and assessment

Return your analysis as a JSON object with this EXACT structure:
{{
  "summary": "Overall assessment of coverage vs. trending attacks (2-3 sentences)",
  "alignment_score": <0-100, where 100 is perfect alignment>,
  "well_covered": [
    {{
      "technique_id": "T1234",
      "technique_name": "Name",
      "rule_count": <count>,
      "trending_rank": <rank>,
      "assessment": "Brief note on why this is well covered"
    }}
  ],
  "under_covered": [
    {{
      "technique_id": "T1234",
      "technique_name": "Name",
      "rule_count": <count>,
      "trending_rank": <rank>,
      "risk_level": "critical|high|medium",
      "recommendation": "Specific action to improve coverage"
    }}
  ],
  "over_represented": [
    {{
      "technique_id": "T1234",
      "technique_name": "Name",
      "rule_count": <count>,
      "observation": "Why this might be over-represented"
    }}
  ]
}}

Important:
- Focus on top 10 items for each category
- Provide actionable insights, not just data repetition
- Consider both coverage quantity and quality
- Return ONLY valid JSON, no additional text
"""

# Anomalies Detection Prompt
ANOMALIES_PROMPT = """
You are a security detection analyst identifying anomalies and unusual patterns in detection rule mappings.

Your task is to find outliers, inconsistencies, and unusual patterns that might indicate issues or opportunities for improvement.

Context - Aggregated Detection Data:
{aggregated_data}

Task: Identify anomalies and unusual patterns including:
1. Detection rules with unusually many or few technique mappings
2. Unexpected tactic and kill-chain combinations
3. Outliers in technique distribution across rules
4. Inconsistencies in coverage patterns
5. Rules that might be mis-classified or need review

Return your findings as a JSON object with this EXACT structure:
{{
  "summary": "Brief overview of key anomalies found (2-3 sentences)",
  "anomalies": [
    {{
      "type": "rule_outlier|mapping_outlier|coverage_outlier|inconsistency",
      "severity": "high|medium|low",
      "description": "Clear description of the anomaly",
      "affected_items": ["List of rule IDs, techniques, or tactics affected"],
      "impact": "Potential impact of this anomaly",
      "recommendation": "Suggested action to address this"
    }}
  ],
  "statistics": {{
    "avg_techniques_per_rule": <average>,
    "rules_with_zero_techniques": <count>,
    "rules_with_many_techniques": <count, e.g., >10>,
    "most_common_technique": "Technique ID and name",
    "least_common_tactic": "Tactic name"
  }}
}}

Important:
- Focus on actionable anomalies (top 10)
- Distinguish between problematic anomalies and interesting patterns
- Provide statistical context where relevant
- Return ONLY valid JSON, no additional text
"""


# Executive Summary Prompt (synthesizes visualization insights)
EXECUTIVE_SUMMARY_PROMPT = """
You are a CISO-level security advisor creating an executive summary of detection coverage.

IMPORTANT - Voice and Tone:
- Use second-person perspective: "your detection coverage", "your rules", "you have"
- DO NOT use first-person plural: avoid "our", "we", "us"
- Write as if advising the reader directly
- Be professional, clear, and actionable

Basic Context (for reference only):
{aggregated_data}

Detailed Visualization Analysis (PRIMARY SOURCE - synthesize these insights):
{visualization_insights}

Your task: Create an EXECUTIVE SUMMARY by synthesizing the visualization insights above.

CRITICAL - Your Analysis Approach:
- Base your analysis ENTIRELY on the visualization insights provided above
- The visualization insights contain detailed analysis of 5 different views of the detection coverage:
  * tactic_coverage: Analysis of MITRE ATT&CK tactic coverage
  * kill_chain_coverage: Analysis of Cyber Kill Chain phase coverage
  * tactic_killchain_heatmap: Analysis of tactic/kill chain intersections
  * top_techniques: Analysis of most frequently detected techniques
  * trending_coverage: Analysis of coverage for real-world trending attacks
- Identify cross-cutting themes and patterns across multiple visualizations
- Synthesize the most critical gaps mentioned across the panels
- Prioritize actions based on insights that appear in multiple visualizations

MANDATORY CONTENT GENERATION:
- You MUST extract ALL actionable recommendations from the visualization insights provided
- NEVER return empty array if there are improvement suggestions in ANY of the 5 visualization panels
- Each visualization panel contains "insights" array with actionable recommendations - extract ALL of these!
- If a panel suggests "consider adding rules for X" or "enhance coverage for Y", this MUST become a priority action
- Look for phrases like "underrepresented", "limited coverage", "only X rules", "gap", "consider", "expand", "enhance"
- Even strong coverage has improvement opportunities - extract them ALL from the visualization insights
- NO LIMITS on number of actions - extract every actionable recommendation mentioned

IMPORTANT - Priority Assignment:
- Assess the overall coverage honestly - if it's strong, say so in the summary!
- Extract ALL recommendations from visualization insights and assign priority levels:
  * CRITICAL: Techniques with high incident % but very low coverage (from trending_coverage insights)
  * HIGH: Issues mentioned in MULTIPLE visualization panels, or critical tactics with significant gaps
  * MEDIUM: Issues mentioned in single panel with moderate impact
  * LOW: Optimization opportunities or nice-to-have improvements
- Be balanced: acknowledge strengths AND extract all improvement opportunities from the visualization analysis

CRITICAL - Actionability Guidelines:
- AVOID action items for Reconnaissance tactic - most organizations lack the signal to detect pre-campaign adversary activities
- AVOID action items for Impact tactic - this is lower value investment, more for mapping adversary intentions than detecting behaviors
- Focus on actionable tactics where organizations can realistically implement detections
- DO NOT suggest "optimizing existing rules" as low effort - this is typically MORE difficult than deploying new coverage
- Prioritize NEW coverage over optimization of existing rules

Analysis requirements:
1. Read through ALL visualization insights to understand the complete picture
2. Extract EVERY actionable recommendation from ALL 5 visualization panels
3. Convert each recommendation into a priority action with appropriate priority level (critical/high/medium/low)
4. Assign CRITICAL priority to: techniques with high incident % but low rule count (from trending_coverage)
5. Assign HIGH priority to: issues mentioned in multiple panels OR critical tactics with significant gaps
6. Assign MEDIUM priority to: issues mentioned in single panel with moderate impact
7. Assign LOW priority to: optimization opportunities or nice-to-have improvements
8. ALWAYS reference which specific visualization(s) support each action
9. EXCLUDE Reconnaissance and Impact tactics unless truly exceptional
10. NO LIMIT on number of actions - extract everything actionable from the insights
11. Sort output by priority: critical first, then high, medium, low

Output EXACTLY this JSON structure:
{{
  "summary_paragraph": "2-3 sentences maximum. Highlight the most critical findings by synthesizing themes across the visualization insights. Direct attention to specific visualizations below.",
  "priority_actions": [
    {{
      "priority": "critical|high|medium|low",
      "action": "Specific action to take (based on recommendations from visualization insights)",
      "rationale": "Why this is priority (synthesize rationale from one or more visualization insights)",
      "estimated_effort": "low|medium|high",
      "expected_impact": "Measurable improvement (from visualization insights or reasonably inferred)"
    }}
  ]
}}

Guidelines:
- summary_paragraph: 2-3 sentences MAXIMUM, highly concise, synthesizing cross-cutting themes
- Use second-person voice ("your coverage", not "our coverage")
- Extract ALL actionable recommendations from visualization insights (NO LIMIT on number of actions)
- Assign priority level to each action: critical, high, medium, or low
- CRITICAL: High incident % techniques with very low rule coverage (from trending_coverage)
- HIGH: Issues in multiple panels OR critical tactics with significant gaps
- MEDIUM: Single-panel issues with moderate impact
- LOW: Optimization opportunities or nice-to-have improvements
- For techniques, include both name and ID: "External Remote Services (T1133)"
- ALWAYS reference which visualization(s) support each action (e.g., "trending coverage shows", "mentioned in tactic coverage analysis")
- Be specific with actions (technique IDs, rule counts from insights, etc.)
- DO NOT mark "optimize existing rules" as low effort - it's typically high effort
- Exclude Reconnaissance and Impact tactics unless exceptional
- Sort actions by priority: critical, high, medium, low
- Return ONLY valid JSON, no markdown formatting or extra text

How to extract from visualization insights:
- tactic_coverage insights: Look for "underrepresented", "limited", "few rules", "consider adding" → becomes priority action
- kill_chain_coverage insights: Look for "limited coverage", "enhance detection", "expand" → becomes priority action
- tactic_killchain_heatmap insights: Look for low rule counts, "underrepresented" → becomes priority action
- top_techniques insights: Look for "consider increasing", "expand coverage" → becomes priority action
- trending_coverage insights: High incident % + low rule count → CRITICAL priority action

Priority Assignment Examples:
- CRITICAL: "T1133 appears in 25% of incidents but has only 2 rules" → critical priority
- HIGH: "Lateral Movement underrepresented in both tactic coverage and heatmap" → high priority
- MEDIUM: "Collection tactic shows underrepresentation" (single panel) → medium priority
- LOW: "Consider optimizing PowerShell detection rules" → low priority

CRITICAL WARNING - DO NOT COPY EXAMPLES:
The examples below are ONLY to show JSON structure format. You MUST generate completely unique content by:
1. Reading the ACTUAL visualization insights data provided above
2. Extracting EVERY recommendation from those insights
3. Using the ACTUAL rule counts, percentages, and recommendations from the data
4. Writing analysis in your own words based on what you find in the visualization insights
5. NEVER copying example text, technique IDs, or numbers shown below

Example action format (DO NOT COPY - generate from actual visualization recommendations):
{{
  "priority": "critical|high|medium|low",
  "action": "[Write specific action based on actual recommendations in visualization insights]",
  "rationale": "[Explain based on actual data and recommendations in visualization insights - reference which panel(s)]",
  "estimated_effort": "low|medium|high",
  "expected_impact": "[Write based on actual context in visualization insights]"
}}
"""

# Per-Visualization Insights Prompt
PER_VISUALIZATION_INSIGHTS_PROMPT = """
You are a expert cybersecurity detection engineer providing concise, actionable insights on a specific detection coverage visualization.

Visualization Context:
- Chart Type: {chart_type}
- Chart Title: {chart_title}
- Description: {chart_description}

Data Shown in This Visualization:
{chart_data}

Full Aggregated Context (for reference):
{aggregated_data}

Task: Provide brief, actionable analysis for THIS SPECIFIC visualization only. Help the user interpret and
understand the data shown in the visualization, concentrating on insights regarding both strengths and
more importantly, gaps and recommendations for improvement.

CRITICAL - Actionability Guidelines:
- AVOID recommendations for Impact tactic - lower value investment, more for mapping intentions than detecting behaviors
- Focus on actionable insights where organizations can realistically implement detections
- DO NOT suggest "optimizing existing rules" as low effort - this is typically MORE difficult than deploying new coverage
- When making recommendations for improvement, ALWAYS explain how implementing your recommendation will improve the
  situation.
- DO NOT imply that better detection can 'prevent' attacks or that gaps are 'vulnerabilities'. You may suggest that
  better detection will improve the organization's ability to detect and respond to attacks if you specify how.
- ALWAYS include the human-readable name of any ATT&CK tactics or techniques as well as the "T number". The preferred format is
  "Tactic/Technique Name (T1234)" or "Subtechnique Name (T1234.001)".
- DO NOT refer to "this visualization" or "this chart". You may assume the user is already aware of the visualization.
  (e.g., NOT "This visualization shows that you have strong coverage for..." but YES "You have strong coverage for...")

Output EXACTLY this JSON structure:
{{
  "description": "3-5 sentences explaining what we can learn from this chart. Be concise and specific.",
  "insights": [
    "Actionable insight 1",
    "Actionable insight 2",
    "Actionable insight 3"
  ]
}}

Guidelines for all charts:
- description: 3-5 sentences MAXIMUM explaining what this chart reveals about the organization's detection and response capability
  or security posture.
- insights: 0-5 items ONLY - include only if there's something actionable or noteworthy
- If nothing actionable to report, return empty insights array: []
- Each insight should reference actual data values from the chart
- Avoid generic observations - be specific and data-driven
- Do NOT include insights about Impact tactics unless exceptional
- Do NOT suggest optimizing existing rules as a recommendation
- Be concise - every word should add value
- If you suggest adding more rules to a tactic/technique/kill chain phase, be specific about which rules you suggest adding and why.
- Return ONLY valid JSON, no additional text

How to generate insights:
- Identify tactics/techniques/kill chain phases that are underrepresented in the organization's detection coverage
- Identify tactics/techniques/kill chain phases that are overrepresented in the organization's detection coverage
- Identify tactics/techniques/kill chain phases that are missing from the organization's detection coverage
- Prioritize under- and over-represented tactics/techniques/kill chain phases by their prevalence in the real world attack
  data and by their potential impact on the organization's security posture, either due to lack of
  coverage or overcoverage.
  - In general, for Kill Chain data, the later phases are more impactful because the adversary is closer to accomplishing their attack's goal.
- When considering tactic coverage, also consider the techniques that fall under it. Just because you have a lot of rules for a
  given tactic doesn't necessarily mean your coverage is strong, especially if they are all for techniques that are less common
  in the wild, less impactful, or if there are many techniques that are not addressed.
- When considering technique coverage, also consider the subtechniques and variants of the technique. Just because you have a lot of rules for a
  given technique doesn't necessarily mean your coverage is strong, especially if they are all for subtechniques or variants that are less common
  in the wild, less impactful, or if there are many subtechniques that are not addressed.

Example for strong coverage:
{{
  "description": "You have detection rules covering nearly every phase of the Cyber Kill Chain, maximizing your ability to detect and respond across the entire attack lifecycle.",
  "insights": []
}}

Example with actionable insights:
{{
  "description": "The vast majority of detection rules are distributed across only about half of the available tactics. Most of these are concerned with initial access, installation, credential theft, and internal reconnaissance.",
  "insights": [
    "Key attacker goals like lateral movement, command and control, and data staging and infiltration have comparatively few rules and while arguably more impactful, are less likely to be detected. Strengthening detection in these areas will improve your chances of detecting and interdicting these types of activities should they occur."
  ]
}}
"""


def get_prompt_template(insight_type: str) -> str:
    """
    Get the prompt template for a specific insight type.

    Args:
        insight_type: Type of insight (coverage_gaps, recommendations, etc.)

    Returns:
        Prompt template string

    Raises:
        ValueError: If insight_type is not recognized
    """
    prompts = {
        "coverage_gaps": COVERAGE_GAPS_PROMPT,
        "recommendations": RECOMMENDATIONS_PROMPT,
        "trends_analysis": TRENDS_ANALYSIS_PROMPT,
        "anomalies": ANOMALIES_PROMPT,
        "executive_summary": EXECUTIVE_SUMMARY_PROMPT,
        "per_visualization": PER_VISUALIZATION_INSIGHTS_PROMPT,
    }

    if insight_type not in prompts:
        raise ValueError(
            f"Unknown insight type: {insight_type}. "
            f"Valid types: {', '.join(prompts.keys())}"
        )

    return prompts[insight_type]


def format_prompt(
    insight_type: str,
    aggregated_data: str = "",
    trending_data: str = "",
    threshold: int = 5,
    visualization_insights: str = "",
    chart_type: str = "",
    chart_title: str = "",
    chart_description: str = "",
    chart_data: str = "",
) -> str:
    """
    Format a prompt template with provided data.

    Args:
        insight_type: Type of insight to generate
        aggregated_data: JSON string of aggregated detection data
        trending_data: JSON string of trending techniques data (optional)
        threshold: Coverage gap threshold
        visualization_insights: JSON string of viz insights (for executive summary)
        chart_type: Type of chart (for per-viz insights)
        chart_title: Title of chart (for per-viz insights)
        chart_description: Description of chart (for per-viz insights)
        chart_data: JSON string of chart-specific data (for per-viz insights)

    Returns:
        Formatted prompt string ready for LLM
    """
    template = get_prompt_template(insight_type)

    # Format the template with provided data
    formatted = template.format(
        aggregated_data=aggregated_data,
        trending_data=trending_data,
        threshold=threshold,
        visualization_insights=visualization_insights,
        chart_type=chart_type,
        chart_title=chart_title,
        chart_description=chart_description,
        chart_data=chart_data,
    )

    return formatted
