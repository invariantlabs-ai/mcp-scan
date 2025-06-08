# src/mcp_scan/report_generator.py
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

class ReportGenerator:
    """스캔 결과 리포트 생성기"""
    
    def __init__(self):
        self.scan_results = []
        self.start_time = datetime.now()
        self.scan_metadata = {
            "version": "0.2.0",
            "scan_id": self._generate_scan_id(),
            "generated_by": "MCP-Scan Enhanced"
        }
    
    def _generate_scan_id(self) -> str:
        """고유한 스캔 ID 생성"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
        return f"{timestamp}_{random_suffix}"
    
    def add_scan_result(self, server_name: str, result: Dict[str, Any]):
        """스캔 결과 추가"""
        scan_entry = {
            'server_name': server_name,
            'timestamp': datetime.now().isoformat(),
            'result': result,
            'issues_count': len(result.get('issues', [])),
            'status': self._determine_status(result),
            'risk_level': self._calculate_risk_level(result)
        }
        self.scan_results.append(scan_entry)
        
    def _determine_status(self, result: Dict[str, Any]) -> str:
        """스캔 결과 상태 결정"""
        if result.get('error'):
            return 'error'
        elif result.get('issues', []):
            return 'warning'
        else:
            return 'success'
    
    def _calculate_risk_level(self, result: Dict[str, Any]) -> str:
        """위험도 계산"""
        issues = result.get('issues', [])
        if not issues:
            return 'none'
        
        high_risk_count = sum(1 for issue in issues if self.categorize_risk_level(issue) == 'high')
        medium_risk_count = sum(1 for issue in issues if self.categorize_risk_level(issue) == 'medium')
        
        if high_risk_count > 0:
            return 'high'
        elif medium_risk_count > 2:
            return 'high'
        elif medium_risk_count > 0:
            return 'medium'
        else:
            return 'low'
    
    def categorize_risk_level(self, issue: Dict[str, Any]) -> str:
        """개별 이슈의 위험도 분류"""
        severity = issue.get('severity', 'low').lower()
        description = issue.get('description', '').lower()
        
        # 키워드 기반 위험도 분류
        high_risk_keywords = ['critical', 'exploit', 'injection', 'execute', 'malicious', 'attack']
        medium_risk_keywords = ['warning', 'suspicious', 'unauthorized', 'insecure']
        
        if severity == 'critical' or any(keyword in description for keyword in high_risk_keywords):
            return 'high'
        elif severity == 'high' or any(keyword in description for keyword in medium_risk_keywords):
            return 'medium'
        else:
            return 'low'
    
    def generate_summary(self) -> Dict[str, Any]:
        """요약 통계 생성"""
        total_servers = len(self.scan_results)
        successful_scans = len([r for r in self.scan_results if r['status'] == 'success'])
        warning_scans = len([r for r in self.scan_results if r['status'] == 'warning'])
        failed_scans = len([r for r in self.scan_results if r['status'] == 'error'])
        
        # 위험도별 이슈 분류
        risk_levels = {'high': 0, 'medium': 0, 'low': 0}
        total_issues = 0
        
        for result in self.scan_results:
            for issue in result['result'].get('issues', []):
                risk = self.categorize_risk_level(issue)
                risk_levels[risk] += 1
                total_issues += 1
        
        scan_duration = datetime.now() - self.start_time
        
        return {
            'scan_metadata': self.scan_metadata,
            'timing': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration': str(scan_duration).split('.')[0],  # 초 단위까지만
                'duration_seconds': int(scan_duration.total_seconds())
            },
            'server_stats': {
                'total_servers': total_servers,
                'successful_scans': successful_scans,
                'warning_scans': warning_scans,
                'failed_scans': failed_scans,
                'success_rate': f"{(successful_scans/total_servers)*100:.1f}%" if total_servers > 0 else "0%"
            },
            'issue_stats': {
                'total_issues': total_issues,
                'high_risk': risk_levels['high'],
                'medium_risk': risk_levels['medium'], 
                'low_risk': risk_levels['low'],
                'risk_distribution': {
                    'high_percentage': f"{(risk_levels['high']/total_issues)*100:.1f}%" if total_issues > 0 else "0%",
                    'medium_percentage': f"{(risk_levels['medium']/total_issues)*100:.1f}%" if total_issues > 0 else "0%",
                    'low_percentage': f"{(risk_levels['low']/total_issues)*100:.1f}%" if total_issues > 0 else "0%"
                }
            }
        }
    def generate_recommendations(self, summary: Dict[str, Any]) -> List[Dict[str, str]]:
        """개선 권장사항 생성"""
        recommendations = []
        
        issue_stats = summary['issue_stats']
        server_stats = summary['server_stats']
        
        # 위험도 기반 권장사항
        if issue_stats['high_risk'] > 0:
            recommendations.append({
                'priority': 'critical',
                'icon': '🚨',
                'title': '긴급 조치 필요',
                'description': f"{issue_stats['high_risk']}개의 높은 위험도 문제가 발견되었습니다. 즉시 검토하고 조치하세요.",
                'actions': [
                    '높은 위험도 문제를 즉시 확인하세요',
                    '관련 MCP 서버를 임시 비활성화하는 것을 고려하세요',
                    '보안 팀에 즉시 보고하세요'
                ]
            })
        
        if issue_stats['medium_risk'] > 5:
            recommendations.append({
                'priority': 'high',
                'icon': '⚠️',
                'title': '정기 점검 권장',
                'description': f"{issue_stats['medium_risk']}개의 중간 위험도 문제가 있습니다. 주기적인 보안 점검을 권장합니다.",
                'actions': [
                    '주 1회 정기 스캔을 수행하세요',
                    'MCP 서버 설정을 검토하세요',
                    '화이트리스트를 업데이트하세요'
                ]
            })
        
        if server_stats['failed_scans'] > 0:
            recommendations.append({
                'priority': 'medium',
                'icon': '🔧',
                'title': '스캔 실패 조사',
                'description': f"{server_stats['failed_scans']}개 서버에서 스캔이 실패했습니다. 설정을 확인해주세요.",
                'actions': [
                    '실패한 서버의 로그를 확인하세요',
                    '서버 경로와 권한을 점검하세요',
                    '네트워크 연결 상태를 확인하세요'
                ]
            })
        
        # 성능 최적화 권장사항
        if summary['timing']['duration_seconds'] > 300:  # 5분 이상
            recommendations.append({
                'priority': 'low',
                'icon': '⚡',
                'title': '성능 최적화',
                'description': '스캔 시간이 길어지고 있습니다. 성능 최적화를 고려해보세요.',
                'actions': [
                    '캐시가 활성화되어 있는지 확인하세요',
                    '불필요한 MCP 서버를 제거하세요',
                    '네트워크 연결을 최적화하세요'
                ]
            })
        
        # 성공적인 경우 권장사항
        if issue_stats['total_issues'] == 0 and server_stats['failed_scans'] == 0:
            recommendations.append({
                'priority': 'info',
                'icon': '✅',
                'title': '보안 상태 양호',
                'description': '심각한 보안 문제가 발견되지 않았습니다. 현재 보안 설정을 유지하세요.',
                'actions': [
                    '현재 보안 설정을 문서화하세요',
                    '월 1회 정기 스캔을 지속하세요',
                    '새로운 MCP 서버 추가 시 사전 검증하세요'
                ]
            })
        
        # 일반적인 권장사항
        recommendations.append({
            'priority': 'info',
            'icon': '📅',
            'title': '정기 보안 관리',
            'description': 'MCP 서버의 지속적인 보안을 위한 일반적인 권장사항입니다.',
            'actions': [
                '월 1회 이상 정기적인 스캔을 수행하세요',
                'MCP 서버 업데이트 시 재스캔하세요',
                '화이트리스트를 정기적으로 검토하세요',
                '팀원들과 보안 가이드라인을 공유하세요'
            ]
        })
        
        return recommendations