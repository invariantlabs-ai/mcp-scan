# tests/test_report_generator.py
import pytest
from datetime import datetime
from src.mcp_scan.report_generator import ReportGenerator

class TestReportGenerator:
    def test_report_initialization(self):
        """리포트 생성기 초기화 테스트"""
        generator = ReportGenerator()
        assert generator.scan_results == []
        assert isinstance(generator.start_time, datetime)
        assert 'version' in generator.scan_metadata
        assert 'scan_id' in generator.scan_metadata
    
    def test_add_scan_result(self):
        """스캔 결과 추가 테스트"""
        generator = ReportGenerator()
        test_result = {
            'issues': [
                {'severity': 'high', 'description': 'test critical issue'},
                {'severity': 'medium', 'description': 'test warning issue'}
            ],
            'status': 'completed'
        }
        
        generator.add_scan_result('test-server', test_result)
        
        assert len(generator.scan_results) == 1
        assert generator.scan_results[0]['server_name'] == 'test-server'
        assert generator.scan_results[0]['issues_count'] == 2
        assert generator.scan_results[0]['status'] == 'warning'
    
    def test_risk_categorization(self):
        """위험도 분류 테스트"""
        generator = ReportGenerator()
        
        high_risk = {'description': 'critical exploit found', 'severity': 'critical'}
        medium_risk = {'description': 'warning detected', 'severity': 'medium'}
        low_risk = {'description': 'minor issue', 'severity': 'low'}
        
        assert generator.categorize_risk_level(high_risk) == 'high'
        assert generator.categorize_risk_level(medium_risk) == 'medium'
        assert generator.categorize_risk_level(low_risk) == 'low'
    
    def test_summary_generation(self):
        """요약 생성 테스트"""
        generator = ReportGenerator()
        
        # 테스트 데이터 추가
        generator.add_scan_result('server1', {
            'issues': [{'severity': 'high', 'description': 'critical issue'}]
        })
        generator.add_scan_result('server2', {
            'issues': []
        })
        
        summary = generator.generate_summary()
        assert summary['server_stats']['total_servers'] == 2
        assert summary['server_stats']['warning_scans'] == 1
        assert summary['server_stats']['successful_scans'] == 1
        assert summary['issue_stats']['total_issues'] == 1
        assert summary['issue_stats']['high_risk'] == 1

def test_recommendations_generation(self):
    """권장사항 생성 테스트"""
    generator = ReportGenerator()
    
    # 높은 위험도 이슈가 있는 요약 데이터
    summary = {
        'issue_stats': {
            'high_risk': 2,
            'medium_risk': 1,
            'low_risk': 0,
            'total_issues': 3
        },
        'server_stats': {
            'failed_scans': 0,
            'total_servers': 2
        },
        'timing': {
            'duration_seconds': 120
        }
    }
    
    recommendations = generator.generate_recommendations(summary)
    
    # 긴급 조치 권장사항이 포함되어야 함
    critical_recs = [r for r in recommendations if r['priority'] == 'critical']
    assert len(critical_recs) > 0
    assert '긴급 조치 필요' in critical_recs[0]['title']