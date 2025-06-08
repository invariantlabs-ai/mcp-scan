import logging
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from typing import Optional

class EnhancedLogger:
    """Rich 라이브러리 기반 향상된 로깅 시스템"""
    
    def __init__(self, show_time: bool = True):
        self.console = Console()
        self.progress: Optional[Progress] = None
        self.setup_logging(show_time)
    
    def setup_logging(self, show_time: bool):
        """Rich 핸들러로 로깅 설정"""
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            handlers=[RichHandler(
                console=self.console, 
                rich_tracebacks=True,
                show_time=show_time,
                show_path=False
            )]
        )
        self.logger = logging.getLogger("mcp_scan")
    
    def info(self, message: str, style: str = ""):
        """정보 메시지"""
        if style:
            self.console.print(message, style=style)
        else:
            self.logger.info(message)
    
    def success(self, message: str):
        """성공 메시지"""
        self.console.print(f"✅ {message}", style="bold green")
    
    def warning(self, message: str):
        """경고 메시지"""
        self.console.print(f"⚠️  {message}", style="bold yellow")
    
    def error(self, message: str):
        """에러 메시지"""
        self.console.print(f"❌ {message}", style="bold red")
    
    def start_progress(self, description: str, total: int) -> int:
        """진행률 바 시작"""
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        )
        self.progress.start()
        return self.progress.add_task(description, total=total)
    
    def update_progress(self, task_id: int, advance: int = 1, description: str = None):
        """진행률 업데이트"""
        if self.progress:
            kwargs = {"advance": advance}
            if description:
                kwargs["description"] = description
            self.progress.update(task_id, **kwargs)
    
    def finish_progress(self):
        """진행률 바 종료"""
        if self.progress:
            self.progress.stop()
            self.progress = None
    
    def print_summary(self, title: str, stats: dict):
        """요약 정보 출력"""
        from rich.table import Table
        
        table = Table(title=f"📊 {title}")
        table.add_column("항목", style="cyan")
        table.add_column("값", style="white")
        
        for key, value in stats.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
