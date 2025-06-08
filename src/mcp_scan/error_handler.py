class ErrorHandler:
    """사용자 친화적 에러 처리"""
    
    ERROR_SOLUTIONS = {
        "FileNotFoundError": {
            "icon": "📁",
            "message": "설정 파일을 찾을 수 없습니다",
            "solutions": [
                "파일 경로가 올바른지 확인하세요",
                "절대 경로를 사용해보세요 (예: /home/user/.config/claude/config.json)",
                "파일 권한을 확인하세요",
                "기본 설정 파일을 생성하세요"
            ]
        },
        "JSONDecodeError": {
            "icon": "📝", 
            "message": "JSON 형식이 올바르지 않습니다",
            "solutions": [
                "온라인 JSON 검증기를 사용하세요 (jsonlint.com)",
                "쉼표, 따옴표, 괄호를 확인하세요",
                "주석은 JSON에서 사용할 수 없습니다"
            ]
        },
        "ConnectionError": {
            "icon": "🌐",
            "message": "네트워크 연결에 문제가 있습니다", 
            "solutions": [
                "인터넷 연결을 확인하세요",
                "--local-only 옵션을 사용해보세요",
                "프록시 설정을 확인하세요"
            ]
        },
        "PermissionError": {
            "icon": "🔒",
            "message": "파일 접근 권한이 없습니다",
            "solutions": [
                "파일 권한을 확인하세요 (chmod 644)",
                "관리자 권한으로 실행해보세요",
                "파일 소유자를 확인하세요"
            ]
        }
    }
    
    @classmethod
    def handle_error(cls, error: Exception) -> str:
        """에러를 사용자 친화적으로 처리"""
        error_type = type(error).__name__
        error_info = cls.ERROR_SOLUTIONS.get(error_type)
        
        if error_info:
            solutions_text = "\n".join(f"  • {sol}" for sol in error_info["solutions"])
            return (
                f"{error_info['icon']} {error_info['message']}\n"
                f"💡 해결 방법:\n{solutions_text}\n"
                f"📋 원본 에러: {error}"
            )
        else:
            return (
                f"❌ 예상치 못한 오류가 발생했습니다: {error}\n"
                f"💡 해결 방법:\n"
                f"  • GitHub 이슈를 등록해주세요\n"
                f"  • --verbose 옵션으로 상세 로그를 확인하세요"
            )