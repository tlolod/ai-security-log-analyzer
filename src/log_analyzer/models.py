"""Shared data models for the AI Security Log Analyzer.

These dataclasses describe the simple pieces of data that move through the
MVP pipeline:

Loader -> Parser -> Detector -> Formatter

Keeping these models small and explicit makes the project easier to understand
and safer to extend later.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class LogEvent:
    """A normalized security event parsed from one raw log line.

    The parser will create this object when it recognizes a useful log line.
    For MVP v1, common event types include ``"failed_login"`` and
    ``"successful_login"``.
    """

    timestamp: datetime
    source_ip: str
    username: Optional[str]
    event_type: str
    raw_line: str


@dataclass
class MitreAttackMetadata:
    """MITRE ATT&CK mapping metadata for a detection rule."""

    tactic: str
    technique_id: str
    technique: str


@dataclass
class Alert:
    """A structured security finding created by a detection rule.

    The detector will create this object when parsed events match suspicious
    behavior, such as many failed logins from the same IP address.
    """

    alert_type: str
    rule_id: str
    rule_name: str
    rule_version: str
    severity: str
    mitre_attack: MitreAttackMetadata | None
    message: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    failed_count: int
    evidence: List[str]


@dataclass
class RunStats:
    """Basic counters that summarize one analyzer run.

    These numbers help beginners understand what happened during processing:
    how many lines were read, how many became events, and how many alerts were
    produced.
    """

    total_lines: int
    parsed_events: int
    skipped_lines: int
    alerts_generated: int
