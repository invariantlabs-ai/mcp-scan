from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class HelpFormatter:
    """CLI 도움말 포맷터"""
    
    @staticmethod
    def show_examples():
        """사용 예시를 Rich 테이블로 출력"""
        console = Console()
        
        # 기본 사용법
        console.print("\n[bold blue]🚀 MCP-Scan 사용 가이드[/bold blue]\n")
        
        basic_table = Table(title="기본 명령어", show_header=True, header_style="bold cyan")
        basic_table.add_column("명령어", style="cyan", width=35)
        basic_table.add_column("설명", style="white")
        
        basic_examples = [
            ("mcp-scan scan", "기본 MCP 서버 스캔 실행"),
            ("mcp-scan scan --verbose", "상세한 로그 출력과 함께 스캔"),
            ("mcp-scan scan config.json", "특정 설정 파일만 스캔"),
            ("mcp-scan inspect", "스캔 없이 도구 목록만 확인"),
            ("mcp-scan whitelist", "화이트리스트 관리"),
        ]
        
        for cmd, desc in basic_examples:
            basic_table.add_row(cmd, desc)
        
        console.print(basic_table)
        console.print()
        
        # 고급 옵션
        advanced_table = Table(title="고급 옵션", show_header=True, header_style="bold yellow")
        advanced_table.add_column("명령어", style="yellow", width=35)
        advanced_table.add_column("설명", style="white")
        
        advanced_examples = [
            ("mcp-scan scan --no-cache", "캐시 무시하고 새로 스캔"),
            ("mcp-scan scan --json", "결과를 JSON 형식으로 출력"),
            ("mcp-scan scan --report report.html", "HTML 리포트 생성"),
            ("mcp-scan --cache-stats", "캐시 사용 통계 출력"),
            ("mcp-scan --clear-cache", "만료된 캐시 정리"),
            ("mcp-scan scan --local-only", "외부 API 없이 로컬 검사만"),
        ]
        
        for cmd, desc in advanced_examples:
            advanced_table.add_row(cmd, desc)
            
        console.print(advanced_table)
        
        # 팁 패널
        tips = Panel.fit(
            "[bold]💡 유용한 팁[/bold]\n\n"
            "• 첫 스캔은 시간이 걸리지만, 이후 캐시로 빨라집니다\n"
            "• --verbose 옵션으로 상세한 진행 상황을 확인하세요\n"
            "• 정기적으로 --clear-cache로 오래된 캐시를 정리하세요\n"
            "• --report 옵션으로 팀과 공유할 수 있는 리포트를 만드세요\n"
            "• 문제 발생 시 --print-errors로 상세 정보를 확인하세요",
            style="green",
            title="[bold green]도움말[/bold green]"
        )
        console.print(tips)
        
        # 설정 파일 위치 안내
        config_panel = Panel.fit(
            "[bold]📁 일반적인 설정 파일 위치[/bold]\n\n"
            "• Claude Desktop: ~/.config/claude/claude_desktop_config.json\n"
            "• Cursor: ~/.cursor/config.json\n"
            "• VS Code: ~/.vscode/extensions/mcp-config.json\n"
            "• 사용자 정의: 임의의 JSON 파일 경로 지정 가능",
            style="blue",
            title="[bold blue]설정 파일[/bold blue]"
        )
        console.print(config_panel)

    @staticmethod
    def show_troubleshooting():
        """문제 해결 가이드 출력"""
        console = Console()
        
        console.print("\n[bold red]🔧 문제 해결 가이드[/bold red]\n")
        
        troubleshooting_table = Table(show_header=True, header_style="bold red")
        troubleshooting_table.add_column("문제", style="red", width=25)
        troubleshooting_table.add_column("해결 방법", style="white", width=50)
        
        issues = [
            (
                "설정 파일을 찾을 수 없음",
                "• 파일 경로 확인\n• 절대 경로 사용\n• 파일 권한 확인"
            ),
            (
                "JSON 형식 오류",
                "• jsonlint.com에서 검증\n• 쉼표, 괄호 확인\n• 주석 제거"
            ),
            (
                "스캔이 느림",
                "• 캐시 활성화 확인\n• 네트워크 상태 확인\n• --local-only 옵션 사용"
            ),
            (
                "서버 시작 실패",
                "• 서버 경로 확인\n• 의존성 설치 확인\n• 포트 충돌 확인"
            ),
        ]
        
        for issue, solution in issues:
            troubleshooting_table.add_row(issue, solution)
        
        console.print(troubleshooting_table)