
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Scanner(str, Enum):
    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    TRIVY = "trivy"


@dataclass
class SecurityFinding:
    scanner: Scanner
    severity: Severity
    title: str
    identifier: str
    location: str
    description: str = ""



class ScanStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


@dataclass
class ScanResult:
    scanner: Scanner
    status: ScanStatus
    findings: list[SecurityFinding]
    error_message: str = ""
