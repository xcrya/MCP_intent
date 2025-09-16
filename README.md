# MCP Intent Analysis System

바이너리 파일의 의도를 자동으로 분석하는 MCP(Model Context Protocol) 기반 시스템입니다.
CAPA, Ghidra, LLM(Claude)을 통합하여 바이너리 파일의 기능과 의도를 종합적으로 분석합니다.

## 주요 기능

### 1. CAPA 분석 (mcp_capa)
- 바이너리 파일의 기능 분석
- 위험도별 기능 분류 (High/Medium/Low Risk)
- MITRE ATT&CK 매핑
- 함수 주소 추출

### 2. 의도 분석 (mcp_intent_llm)
- CAPA 분석 결과 기반 의도 추론
- 위협 수준 평가
- 악성 행위 패턴 식별
- 상세 분석 보고서 생성
- AI 기반 심층 분석

## 프로젝트 구조

```
MCP_intent/
├── analyzed/           # 분석 결과 저장 디렉토리
│   └── [세션명]/      # 각 분석 세션별 결과
│       ├── CAPA_result.json
│       └── intent_report.json
├── binary/            # 분석 대상 바이너리 파일 저장
├── mcp_capa/          # CAPA 분석 MCP 서버
│   ├── requirements.txt
│   └── server.py
└── mcp_intent_llm/    # 의도 분석 MCP 서버
    ├── requirements.txt
    └── server.py

```

## 시스템 요구사항

### 1. CAPA 관련
- CAPA 도구 (버전 7.4.0 이상)
- CAPA Rules 및 Signatures 필요
  - [capa-rules](https://github.com/mandiant/capa-rules)
  - [capa-sigs](https://github.com/mandiant/capa-sigs) # 현재 링크 접속x 

### 2. Python 환경
- Python 3.10 이상
- 각 서버별 가상환경 권장

### 3. 운영체제별 주의사항
#### Windows
- 절대 경로 설정 시 백슬래시(`\`) 사용
  ```python
  # server.py의 경로 설정 예시
  USER_PATH = Path("C:\\Users\\사용자이름")
  BASE_DIR = USER_PATH / "MCP_intent"
  ```
- Python 가상환경 구조:
  ```
  venv/
  ├── Scripts/       # 실행 파일 디렉토리
  │   ├── python.exe
  │   ├── pip.exe
  │   └── activate.bat
  ├── Lib/
  └── Include/
  ```
- server.py 첫 줄 수정 (shebang 제거 또는 수정)
  ```python
  # Windows에서는 shebang 라인이 필요 없음
  ```
- 가상환경 활성화:
  ```cmd
  .\venv\Scripts\activate
  ```
- 터미널에서 한글 출력 시 인코딩 설정:
  ```cmd
  chcp 65001
  ```

#### macOS/Linux
- 절대 경로 설정 시 슬래시(`/`) 사용
  ```python
  USER_PATH = Path("/Users/사용자이름")
  BASE_DIR = USER_PATH / "MCP_intent"
  ```
- Python 가상환경 구조:
  ```
  venv/
  ├── bin/           # 실행 파일 디렉토리
  │   ├── python
  │   ├── pip
  │   └── activate
  ├── lib/
  └── include/
  ```
- server.py 첫 줄 예시:
  ```python
  #!/Users/사용자이름/MCP_intent/mcp_intent_llm/venv/bin/python
  ```
- 가상환경 활성화:
  ```bash
  source venv/bin/activate
  ```

## 설치 방법

### 1. 저장소 클론
```bash
git clone https://github.com/xcrya/MCP_intent.git
cd MCP_intent
```

### 2. 초기 설정
1. 각 서버의 `server.py` 파일에서 경로 설정 수정
   - Windows: `USER_PATH = Path("C:\\Users\\사용자이름")`
   - macOS/Linux: `USER_PATH = Path("/Users/사용자이름")`

2. 필요한 디렉토리 생성
```bash
mkdir -p binary analyzed
```

### 3. CAPA 분석 서버 설정
#### Windows
```cmd
cd mcp_capa
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

#### macOS/Linux
```bash
cd mcp_capa
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 주요 분석 항목

1. 위험도 평가
   - Critical: 매우 높은 위험도, 즉각적인 조치 필요
   - High: 높은 위험도, 주의 깊은 모니터링 필요
   - Medium: 중간 위험도, 지속적인 관찰 필요
   - Low: 낮은 위험도, 일반적인 주의 필요

2. 의도 분석 카테고리
   - data_theft: 데이터 탈취
   - system_compromise: 시스템 장악
   - persistence: 지속성 확보
   - evasion: 탐지 회피
   - reconnaissance: 정보 수집
   - 기타 카테고리...

3. 보안 분석 항목
   - 주요 보안 우려사항
   - 의심스러운 패턴
   - 탐지 회피 기법
   - 데이터 수집 기능

## 라이선스
MIT License
```bash
cd mcp_intent_llm
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 서버별 requirements.txt

### mcp_capa/requirements.txt
```
flare-capa>=7.4.0
mcp>=1.0.0
fastmcp>=0.3.0
pydantic>=2.0.0
click>=8.0.0
```

### mcp_intent_llm/requirements.txt
```
anthropic>=0.25.0
mcp>=1.0.0
fastmcp>=0.3.0
pydantic>=2.0.0
click>=8.0.0
```

## 사용 방법

1. CAPA 분석 서버 실행
```bash
cd mcp_capa
source venv/bin/activate
python server.py
```

2. 의도 분석 서버 실행
```bash
cd mcp_intent_llm
source venv/bin/activate
python server.py
```

3. 분석 결과 확인
- 분석 결과는 `analyzed/[세션명]/` 디렉토리에 저장됨
  - `CAPA_result.json`: CAPA 분석 결과
  - `intent_report.json`: 의도 분석 결과 및 종합 보고서

각 서버의 설정에서 다음 경로들을 실제 환경에 맞게 수정:

**mcp_capa/server.py:**
```python
CAPA_ENV = Path("/path/to/your/capa-env")  # CAPA 설치 경로
CAPA_RULES = Path("/path/to/capa-rules")   # capa-rules 클론 경로
CAPA_SIGS = Path("/path/to/capa-sigs")     # capa-sigs 클론 경로 (선택)
BASE_DIR = Path("/path/to/MCP_intent")     # 프로젝트 루트 경로
```

### 4. 환경 변수 설정 (선택)

API 키가 필요한 경우:
```bash
export OPENAI_API_KEY="your-openai-key"
export ANTHROPIC_API_KEY="your-anthropic-key"
```

## 사용법

### 0. 분석할 바이너리가 있는 파일 지정

### 1. 단일 파일 분석
```python
# CAPA 분석
mcp__capa-analyzer__analyze_single(binary_path="path/to/malware.exe", session_name="test1")

# Ghidra 분석
mcp__pyghidra-analyzer__analyze_single(session_name="test1", binary_path="path/to/malware.exe")

# 의도 분석
mcp__intent-analyzer__analyze_single(session_name="test1")
```

### 2. 폴더 전체 분석
```python
# 폴더 내 모든 실행파일 분석
mcp__capa-analyzer__analyze_folder(folder_path="path/to/malware_folder", base_session_name="batch1")
mcp__pyghidra-analyzer__analyze_folder(base_session_name="batch1", folder_path="path/to/malware_folder")
mcp__intent-analyzer__analyze_folder(base_session_name="batch1")
```

## 지원 파일 형식

- **Windows PE** (.exe, .dll)
- **Linux ELF**
- **기타 CAPA 지원 형식**

**주의**: macOS Mach-O 바이너리는 현재 CAPA가 지원하지 않음.

## 출력 구조

```
analyzed/
├── session_name/
│   ├── CAPA_result.json      # CAPA 분석 결과
│   ├── pyghidra_result.json  # Ghidra 디컴파일 결과 (이후 기드라 연결 필요)
│   └── intent_report.json    # 최종 의도 분석 보고서
```

## 문제 해결

1. **CAPA "지원되지 않는 파일" 오류**: 파일 형식이 PE/ELF인지 확인
2. **pyghidra 오류**: Ghidra 설치 및 !!경로 설정!! 확인
3. **경로 오류**: server.py 파일들의 절대 경로 설정 확인
