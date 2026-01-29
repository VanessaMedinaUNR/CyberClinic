#Cyber Clinic - Severity mapper and CVSS calculator
#Maps findings to severity levels with CVSS scoring

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class SeverityMapper:
    """Map security findings to severity levels and CVSS scores"""
    
    #severity to numeric mapping
    SEVERITY_LEVELS = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1
    }
    
    #severity to CVSS score range mapping
    CVSS_RANGES = {
        'critical': (9.0, 10.0),
        'high': (7.0, 8.9),
        'medium': (4.0, 6.9),
        'low': (0.1, 3.9),
        'info': (0.0, 0.0)
    }
    
    #color scheme for reports
    SEVERITY_COLORS = {
        'critical': '#8B0000', 
        'high': '#DC143C',    
        'medium': '#FF8C00',   
        'low': '#FFD700',      
        'info': '#4682B4'     
    }
    
    def __init__(self):
        pass
    
    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a finding with CVSS score and additional metadata"""
        severity = finding.get('severity', 'info').lower()
        
        #calculate CVSS score
        cvss_score = self._calculate_cvss_score(finding)
        
        #get severity level from score if needed
        if cvss_score > 0:
            severity = self._cvss_to_severity(cvss_score)
        
        #enrich finding
        finding['severity'] = severity
        finding['severity_level'] = self.SEVERITY_LEVELS.get(severity, 1)
        finding['cvss'] = {
            'score': cvss_score,
            'severity': severity.upper(),
            'color': self.SEVERITY_COLORS[severity]
        }
        
        #add priority (for sorting)
        finding['priority'] = self._calculate_priority(finding)
        
        return finding
    
    def _calculate_cvss_score(self, finding: Dict[str, Any]) -> float:
        """Calculate CVSS score based on finding characteristics"""
        severity = finding.get('severity', 'info').lower()
        finding_type = finding.get('type', '')
        
        #start with base score from severity
        min_score, max_score = self.CVSS_RANGES[severity]
        base_score = (min_score + max_score) / 2
        
        #adjust based on finding type
        if finding_type == 'vulnerability':
            #actual vulnerabilities get higher scores
            base_score = max(base_score, 7.0)
        
        elif finding_type == 'unencrypted_service':
            #unencrypted services are medium-high risk
            base_score = max(base_score, 5.0)
        
        elif finding_type == 'outdated_service':
            #outdated software is high risk
            base_score = max(base_score, 7.5)
        
        elif finding_type == 'web_vulnerability':
            #web vulns vary by type
            description = finding.get('description', '').lower()
            
            if any(word in description for word in ['sql injection', 'rce', 'remote code']):
                base_score = 9.5
            elif any(word in description for word in ['xss', 'csrf', 'xxe']):
                base_score = 7.5
            elif any(word in description for word in ['disclosure', 'exposed']):
                base_score = 5.5
            else:
                base_score = max(base_score, 4.0)
        
        elif finding_type == 'open_ports':
            #open ports are info unless many are open
            details = finding.get('details', {})
            port_count = len(details.get('ports', []))
            if port_count > 10:
                base_score = 4.0
            elif port_count > 5:
                base_score = 2.0
            else:
                base_score = 0.0
        
        #ensure score is within valid range
        return round(min(10.0, max(0.0, base_score)), 1)
    
    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        elif score > 0.0:
            return 'low'
        else:
            return 'info'
    
    def _calculate_priority(self, finding: Dict[str, Any]) -> int:
        """Calculate priority for sorting (higher = more important)"""
        severity_level = finding.get('severity_level', 1)
        cvss_score = finding.get('cvss', {}).get('score', 0.0)
        
        #priority = severity_level * 1000 + cvss_score * 100
        #this ensures critical findings come first, then sorted by CVSS within each level
        return int(severity_level * 1000 + cvss_score * 100)
    
    def aggregate_findings_stats(self, findings: list) -> Dict[str, Any]:
        """Calculate statistics for findings"""
        stats = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in stats:
                stats[severity] += 1
        
        #calculate risk score (weighted sum)
        stats['risk_score'] = (
            stats['critical'] * 10 +
            stats['high'] * 7 +
            stats['medium'] * 4 +
            stats['low'] * 2 +
            stats['info'] * 0
        )
        
        #determine overall risk level
        if stats['critical'] > 0:
            stats['overall_risk'] = 'Critical'
        elif stats['high'] > 2:
            stats['overall_risk'] = 'High'
        elif stats['high'] > 0 or stats['medium'] > 5:
            stats['overall_risk'] = 'Medium'
        elif stats['medium'] > 0 or stats['low'] > 5:
            stats['overall_risk'] = 'Low'
        else:
            stats['overall_risk'] = 'Minimal'
        
        return stats
    
    def get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        return self.SEVERITY_COLORS.get(severity.lower(), '#808080')
    
    def sort_findings(self, findings: list) -> list:
        """Sort findings by priority (most severe first)"""
        return sorted(findings, key=lambda f: f.get('priority', 0), reverse=True)

# Done by Morales-Marroquin
