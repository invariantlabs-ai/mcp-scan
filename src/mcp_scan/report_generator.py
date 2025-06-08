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

    def _generate_summary_stats_html(self, summary: Dict[str, Any]) -> str:
        """요약 통계 섹션의 HTML을 생성합니다."""
        total_issues_risk_class = 'risk-medium' if summary['issue_stats']['total_issues'] > 0 else 'risk-success'

        html_output = f"""
<div class="section">
    <div class="stats-grid">
        <div class="stat-card risk-success">
            <h3>총 서버 수</h3>
            <span class="number">{summary['server_stats']['total_servers']}</span>
            <div class="description">스캔 대상 서버</div>
        </div>
        <div class="stat-card risk-success">
            <h3>스캔 성공률</h3>
            <span class="number">{summary['server_stats']['success_rate']}</span>
            <div class="description">전체 대비 성공률</div>
        </div>
        <div class="stat-card {total_issues_risk_class}">
            <h3>총 발견 이슈</h3>
            <span class="number">{summary['issue_stats']['total_issues']}</span>
            <div class="description">보안 문제 및 권장사항</div>
        </div>
        <div class="stat-card risk-success">
            <h3>스캔 소요시간</h3>
            <span class="number">{summary['timing']['duration']}</span>
            <div class="description">전체 스캔 시간</div>
        </div>
    </div>
"""

        if summary['issue_stats']['total_issues'] > 0:
            html_output += f"""
    <div class="stats-grid">
        <div class="stat-card risk-high">
            <h3>높은 위험도</h3>
            <span class="number">{summary['issue_stats']['high_risk']}</span>
            <div class="description">{summary['issue_stats']['risk_distribution']['high_percentage']}</div>
        </div>
        <div class="stat-card risk-medium">
            <h3>보통 위험도</h3>
            <span class="number">{summary['issue_stats']['medium_risk']}</span>
            <div class="description">{summary['issue_stats']['risk_distribution']['medium_percentage']}</div>
        </div>
        <div class="stat-card risk-low">
            <h3>낮은 위험도</h3>
            <span class="number">{summary['issue_stats']['low_risk']}</span>
            <div class="description">{summary['issue_stats']['risk_distribution']['low_percentage']}</div>
        </div>
    </div>
"""

        html_output += "</div>"
        return html_output

    def _generate_recommendations_list_html(self, recommendations: List[Dict[str, str]]) -> str:
        """권장사항 목록의 HTML을 생성합니다."""
        recommendations_html = ""
        for rec in recommendations:
            actions_list_html = ""
            if rec.get('actions'):
                for action in rec['actions']:
                    actions_list_html += f"<li>{action}</li>"
                actions_list_html = f"<ul class='actions-list'>{actions_list_html}</ul>"
            
            recommendations_html += f"""
<div class='recommendation priority-{rec['priority']}'>
    <div class='recommendation-header'>
        <div class='icon'>{rec['icon']}</div>
        <div class='recommendation-content'>
            <h4>{rec['title']}</h4>
            <p>{rec['description']}</p>
            {actions_list_html}
        </div>
    </div>
</div>
"""
        return f"""
<div class="section">
    <h2 class="section-title">📋 보안 권장사항</h2>
    <div class="recommendations">
        {recommendations_html}
    </div>
</div>
"""

    def _generate_servers_list_html(self, scan_results: List[Dict[str, Any]]) -> str:
        """서버별 결과 목록의 HTML을 생성합니다."""
        servers_html = ""
        for result in scan_results:
            status_text = {
                'success': '정상',
                'warning': '경고',
                'error': '오류'
            }.get(result['status'], '')
            
            risk_level_text = {
                'high': '높음',
                'medium': '보통',
                'low': '낮음',
                'none': '없음'
            }.get(result['risk_level'], '')

            servers_html += f"""
<div class='server-item status-{result['status']}'>
    <div class='server-header'>
        <div class='server-name'>{result['server_name']}</div>
        <span class='status-badge status-{result['status']}'>
            {status_text}
        </span>
    </div>
    <div class='server-details'>
        <div class='detail-item'>
            <div class='detail-label'>스캔 시간</div>
            <div class='detail-value'>{result['timestamp'].split('T')[1].split('.')[0]}</div>
        </div>
        <div class='detail-item'>
            <div class='detail-label'>발견된 이슈</div>
            <div class='detail-value'>{result['issues_count']}개</div>
        </div>
        <div class='detail-item'>
            <div class='detail-label'>위험도</div>
            <div class='detail-value'>
                {risk_level_text}
            </div>
        </div>
    </div>
</div>
"""
        return f"""
<div class="section">
    <h2 class="section-title">📊 서버별 스캔 결과</h2>
    <div class="servers-grid">
        {servers_html}
    </div>
</div>
"""

    def generate_html_report(self, output_path: str = None) -> str:
        """HTML 리포트 생성"""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"mcp_scan_report_{timestamp}.html"
        
        summary = self.generate_summary()
        recommendations = self.generate_recommendations(summary)
        
        # 각 섹션의 HTML 생성
        summary_stats_html = self._generate_summary_stats_html(summary)
        recommendations_list_html = self._generate_recommendations_list_html(recommendations)
        servers_list_html = self._generate_servers_list_html(self.scan_results)
        
        # 메인 HTML 템플릿 로드
        html_template = self._get_html_template()
        
        # 플레이스홀더 채우기
        html_content = html_template.format(
            REPORT_TITLE=summary['scan_metadata']['generated_by'] + " 보안 분석 리포트",
            GENERATED_AT=datetime.now().strftime("%Y년 %m월 %d일 %H:%M:%S"),
            SCAN_ID=summary['scan_metadata']['scan_id'],
            SUMMARY_STATS_HTML=summary_stats_html,
            RECOMMENDATIONS_HTML=recommendations_list_html,
            SERVERS_HTML=servers_list_html,
            VERSION=summary['scan_metadata']['version'],
            GENERATED_BY=summary['scan_metadata']['generated_by']
        )
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_file.absolute())
    
    def _get_html_template(self) -> str:
        """HTML 템플릿을 반환합니다. 동적인 내용은 플레이스홀더로 표시됩니다."""
        return '''
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{REPORT_TITLE}</title>
    <style>
        * {{ 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Malgun Gothic', sans-serif;
            line-height: 1.6;
            color: #2d3748;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            overflow: hidden;
            animation: slideUp 0.6s ease-out;
        }}
        
        @keyframes slideUp {{
            from {{ opacity: 0; transform: translateY(30px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 50px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); opacity: 0.5; }}
            50% {{ transform: scale(1.1); opacity: 0.8; }}
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 15px;
            font-weight: 300;
            position: relative;
            z-index: 1;
        }}
        
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.2em;
            position: relative;
            z-index: 1;
        }}
        
        .header .scan-id {{
            margin-top: 10px;
            font-size: 0.9em;
            opacity: 0.7;
            font-family: 'Courier New', monospace;
        }}
        
        .content {{
            padding: 50px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin-bottom: 50px;
        }}
        
        .stat-card {{
            background: linear-gradient(145deg, #f7fafc, #edf2f7);
            padding: 35px;
            border-radius: 20px;
            text-align: center;
            border: 1px solid #e2e8f0;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--accent-color, #667eea);
        }}
        
        .stat-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }}
        
        .stat-card h3 {{
            color: #4a5568;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            font-weight: 600;
        }}
        
        .stat-card .number {{
            font-size: 3em;
            font-weight: 800;
            color: #2d3748;
            margin-bottom: 8px;
            display: block;
        }}
        
        .stat-card .description {{
            color: #718096;
            font-size: 0.9em;
        }}
        
        .risk-high {{ --accent-color: #e53e3e; color: #e53e3e !important; }}
        .risk-medium {{ --accent-color: #dd6b20; color: #dd6b20 !important; }}
        .risk-low {{ --accent-color: #38a169; color: #38a169 !important; }}
        .risk-success {{ --accent-color: #00b4d8; color: #00b4d8 !important; }}
        
        .section {{
            margin-bottom: 50px;
        }}
        
        .section-title {{
            font-size: 2.2em;
            color: #2d3748;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e2e8f0;
            position: relative;
        }}
        
        .section-title::after {{
            content: '';
            position: absolute;
            bottom: -3px;
            left: 0;
            width: 60px;
            height: 3px;
            background: #667eea;
        }}
        
        .recommendations {{
            display: grid;
            gap: 20px;
        }}
        
        .recommendation {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            border-left: 5px solid var(--rec-color);
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }}
        
        .recommendation:hover {{
            transform: translateX(5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
        }}
        
        .recommendation.priority-critical {{ --rec-color: #e53e3e; background: #fed7d7; }}
        .recommendation.priority-high {{ --rec-color: #dd6b20; background: #feebc8; }}
        .recommendation.priority-medium {{ --rec-color: #3182ce; background: #bee3f8; }}
        .recommendation.priority-low, .recommendation.priority-info {{ --rec-color: #38a169; background: #c6f6d5; }}
        
        .recommendation-header {{
            display: flex;
            align-items: flex-start;
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .recommendation .icon {{
            font-size: 2em;
            min-width: 50px;
            text-align: center;
        }}
        
        .recommendation-content h4 {{
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 1.3em;
            font-weight: 600;
        }}
        
        .recommendation-content p {{
            color: #4a5568;
            margin-bottom: 15px;
        }}
        
        .actions-list {{
            list-style: none;
        }}
        
        .actions-list li {{
            padding: 8px 0;
            color: #2d3748;
            position: relative;
            padding-left: 25px;
        }}
        
        .actions-list li::before {{
            content: '▶';
            position: absolute;
            left: 0;
            color: var(--rec-color);
            font-size: 0.8em;
        }}
        
        .servers-grid {{
            display: grid;
            gap: 20px;
        }}
        
        .server-item {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            border-left: 5px solid var(--server-color);
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }}
        
        .server-item:hover {{
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
        }}
        
        .server-item.status-success {{ --server-color: #38a169; }}
        .server-item.status-warning {{ --server-color: #dd6b20; }}
        .server-item.status-error {{ --server-color: #e53e3e; }}
        
        .server-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .server-name {{
            font-weight: 700;
            color: #2d3748;
            font-size: 1.2em;
        }}
        
        .status-badge {{
            padding: 6px 16px;
            border-radius: 25px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .status-success {{
            background: #c6f6d5;
            color: #22543d;
        }}
        
        .status-warning {{
            background: #feebc8;
            color: #744210;
        }}
        
        .status-error {{
            background: #fed7d7;
            color: #742a2a;
        }}
        
        .server-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .detail-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .detail-label {{
            font-size: 0.85em;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }}
        
        .detail-value {{
            font-weight: 600;
            color: #2d3748;
        }}
        
        .footer {{
            background: #f7fafc;
            padding: 40px;
            text-align: center;
            color: #718096;
            border-top: 1px solid #e2e8f0;
        }}
        
        .footer-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .footer-logo {{
            font-weight: 700;
            color: #4a5568;
        }}
        
        .footer-info {{
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .container {{ margin: 10px; }}
            .content, .header {{ padding: 30px 20px; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
            .server-header {{ flex-direction: column; align-items: flex-start; }}
            .footer-content {{ flex-direction: column; text-align: center; }}
        }}
        
        .progress-ring {{
            width: 120px;
            height: 120px;
            margin: 0 auto 20px;
        }}
        
        .progress-ring circle {{
            fill: none;
            stroke-width: 8;
        }}
        
        .progress-ring .bg {{
            stroke: #e2e8f0;
        }}
        
        .progress-ring .progress {{
            stroke: var(--accent-color, #667eea);
            stroke-linecap: round;
            transition: stroke-dasharray 0.5s ease;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 {REPORT_TITLE}</h1>
            <div class="subtitle">{GENERATED_AT} 생성</div>
            <div class="scan-id">스캔 ID: {SCAN_ID}</div>
        </div>
        
        <div class="content">
            <!-- 요약 통계 -->
            {SUMMARY_STATS_HTML}
            
            <!-- 권장사항 -->
            {RECOMMENDATIONS_HTML}
            
            <!-- 서버별 결과 -->
            {SERVERS_HTML}
        </div>
        
        <div class="footer">
            <div class="footer-content">
                <div class="footer-logo">MCP-Scan Enhanced v{VERSION}</div>
                <div class="footer-info">
                    생성자: {GENERATED_BY} | 
                    스캔 ID: {SCAN_ID}
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''