import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class SecurityFinding:
    title: str
    severity: str
    description: str
    remediation: str
    confidence: int = 85
    path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }
        if self.path:
            result["path"] = self.path
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class BaseSecurityChecker(ABC):
    
    def __init__(self, target: str, timeout: int = 10, logger: Optional[logging.Logger] = None):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        self.target = target
        self.timeout = timeout
        self.findings: List[SecurityFinding] = []
        self.logger = logger or logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def run_all_checks(self) -> List[Dict[str, Any]]:
        pass
    
    def add_finding(self, finding: SecurityFinding) -> None:
        self.findings.append(finding)
        self.logger.info(
            f"Finding: {finding.severity.upper()} - {finding.title}"
        )
    
    def get_findings(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self.findings]
    
    def clear_findings(self) -> None:
        self.findings = []