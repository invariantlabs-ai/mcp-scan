# MCP-Scan Docker Image

## Goal
기존 MCP-Scan의 복잡한 에러 메시지, 느린 스캔 속도, 부족한 사용성 문제를 해결하기 위해 사용자 친화적 에러 처리, 스마트 캐싱, 실시간 진행률 표시, HTML 리포트 생성 기능을 추가하여 시각화를 개선했습니다.

## Requirements
- Python >= 3.11
- uv >= 0.1.0
- mcp-scan >= 0.2.1
- pyjson5 >= 1.0.1
- rich >= 13.0.0
- pydantic >= 2.0.0

## How to install & Run

### Docker image 다운로드 및 설치
```bash
# 이미지 다운로드
docker pull final_2023040040:v1

# 또는 로컬에서 빌드
docker build -t final_2023040040:v1 .
```

### Docker container 생성하고 실행
```bash
# 컨테이너 생성 및 실행 (기본 테스트)
docker run -it --rm \
  -v "$(pwd)/test_data:/root/Project/test_data" \
  -v "$(pwd)/report.html:/root/Project/report.html" \
  final_2023040040:v1 scan /root/Project/test_data/simple_mcp_config.json --report /root/Project/report.html

# 상세 로그와 함께 실행
docker run -it --rm \
  -v "$(pwd)/test_data:/root/Project/test_data" \
  -v "$(pwd)/report.html:/root/Project/report.html" \
  final_2023040040:v1 scan /root/Project/test_data/simple_mcp_config.json --report /root/Project/report.html --verbose
```

### 테스트 설정 파일 설명
`test_data/simple_mcp_config.json` 파일에는 두 개의 테스트 서버가 설정되어 있습니다:

1. `echo-server`: 간단한 echo 명령어를 실행하는 서버
   - 명령어: `echo "Hello from MCP Server!"`
   - 목적: 기본적인 서버 연결 테스트

2. `file-server`: 프로젝트 디렉토리 목록을 보여주는 서버
   - 명령어: `ls /root/Project`
   - 목적: 파일시스템 접근 테스트

### 디렉토리 구조
```
/root/Project/
├── README.md         # 프로젝트 설명
├── Dockerfile        # Docker 이미지 빌드 설정
├── src/              # 소스 코드
│   └── mcp_scan/     # MCP 스캐너 구현
├── test_data/        # 테스트 데이터
│   └── simple_mcp_config.json  # MCP 설정 파일
└── report.html       # 생성된 리포트
```

### 실행을 마치고 종료하는 방법
- 컨테이너는 `--rm` 옵션으로 실행되므로, 프로세스가 종료되면 자동으로 컨테이너가 삭제됩니다.
- 리포트는 볼륨 마운트를 통해 호스트 시스템에 저장됩니다.

### 테스트 결과 확인
1. HTML 리포트 확인:
   - `report.html` 파일을 웹 브라우저에서 열어 스캔 결과를 확인할 수 있습니다.
   - 리포트에는 서버 상태, 보안 이슈, 성공률 등이 포함됩니다.

2. 로그 확인:
   - `--verbose` 옵션을 사용하면 상세한 로그를 볼 수 있습니다.
   - 각 서버의 연결 상태와 스캔 진행 상황을 확인할 수 있습니다.

