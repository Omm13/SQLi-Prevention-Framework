"""Heuristic SQL-injection *indicator* detection.

This is a monitoring aid, not a defense. The defense is the parameterized
query. The detector exists so that an attempt leaves a visible trace in the
security log, which is the Security Information Management part of the
project.

Heuristics are deliberately simple and explainable. Each rule has a name and
a severity weight so the dashboard can show *why* an event was flagged.
Because naive pattern matching produces false positives (e.g. the surname
O'Brien), the rules look for combinations, not a lone apostrophe.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    pattern: re.Pattern


RULES = [
    Rule(
        "quote_then_boolean",
        "A quote followed by OR/AND and a comparison (tautology-style input)",
        re.compile(r"'\s*(or|and)\s+['\"\w]+\s*=", re.IGNORECASE),
    ),
    Rule(
        "comment_sequence",
        "SQL comment markers used to cut off the rest of a query",
        re.compile(r"(--|/\*|#\s*$)"),
    ),
    Rule(
        "union_select",
        "UNION ... SELECT used to append another query's results",
        re.compile(r"\bunion\b.+\bselect\b", re.IGNORECASE),
    ),
    Rule(
        "statement_terminator",
        "A semicolon followed by another SQL keyword",
        re.compile(
            r";\s*(select|insert|update|delete|drop|alter|create)\b",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "sleep_or_benchmark",
        "Time-delay functions sometimes used to probe a database",
        re.compile(r"\b(sleep|pg_sleep|benchmark|waitfor)\s*\(", re.IGNORECASE),
    ),
]


def inspect(*values):
    """Return the sorted list of rule names triggered by the given strings."""
    hits = set()
    for value in values:
        if not value:
            continue
        for rule in RULES:
            if rule.pattern.search(value):
                hits.add(rule.name)
    return sorted(hits)


def severity_for(hits):
    """Map the number of distinct indicators to a plain-language severity."""
    if not hits:
        return "none"
    if len(hits) == 1:
        return "medium"
    return "high"
