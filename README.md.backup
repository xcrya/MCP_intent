# MCP Intent Analysis System

의도 분석 MCP관련 정리... CAPA, Ghidra, LLM을 활용하여 바이너리 파일을 분석함.
capa - pyghidra - llm 을 이어주는 다리(claude code) 구현 필요

## 시스템 요구사항

### 1. CAPA (Capability Analysis)
- **CAPA 도구 설치 필요**
  - [CAPA 릴리즈 페이지](https://github.com/mandiant/capa/releases)에서 다운로드
  - 또는 `pip install flare-capa>=7.4.0`로 설치
- **CAPA Rules 및 Signatures**
  - [capa-rules](https://github.com/mandiant/capa-rules) 클론 필요
  - [capa-sigs](https://github.com/mandiant/capa-sigs) 클론 필요 (선택사항)

### 2. Ghidra
- **Ghidra 설치 필요**
  - [NSA Ghidra](https://github.com/NationalSecurityAgency/ghidra) 다운로드 및 설치
  - Java 17+ 필요
- **pyghidra 라이브러리**
  - `pip install pyghidra` 설치 후 Ghidra 경로 설정 필요

### 3. Python 환경
- Python 3.10+ 필수

## 설치 방법

### 1. 기본 환경 구성
```bash
# CAPA 설치
pip install flare-capa>=7.4.0

# CAPA Rules & Sigs 클론
git clone https://github.com/mandiant/capa-rules.git
git clone https://github.com/mandiant/capa-sigs.git

# Ghidra 설치 및 pyghidra 설정
pip install pyghidra
# Ghidra 경로 설정 필요 (첫 실행 시 자동으로 안내)
```

### 2. MCP 서버들 설치

#### CAPA 분석 서버
```bash
cd mcp_capa
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**requirements.txt (mcp_capa):**
```
flare-capa>=7.4.0
mcp>=1.0.0
fastmcp>=0.3.0
pydantic>=2.0.0
click>=8.0.0
```

#### Ghidra 분석 서버
```bash
cd mcp_pyghidra
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install pyghidra  # Ghidra 연동 필요
```

**requirements.txt (mcp_pyghidra):**
```
mcp>=1.0.0
fastmcp>=0.3.0
pydantic>=2.0.0
click>=8.0.0
httpx>=0.25.0
pyghidra
```

#### 의도 분석 LLM 서버
```bash
cd mcp_intent_llm
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**requirements.txt (mcp_intent_llm):**
```
openai>=1.0.0
anthropic>=0.25.0
mcp>=1.0.0
fastmcp>=0.3.0
pydantic>=2.0.0
click>=8.0.0
langchain>=0.1.0
llama-index>=0.10.0
```

### 3. 서버 설정 파일 수정

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
│   ├── pyghidra_result.json  # Ghidra 디컴파일 결과
│   └── intent_report.json    # 최종 의도 분석 보고서
```

## 문제 해결

1. **CAPA "지원되지 않는 파일" 오류**: 파일 형식이 PE/ELF인지 확인
2. **pyghidra 오류**: Ghidra 설치 및 경로 설정 확인
3. **경로 오류**: server.py 파일들의 절대 경로 설정 확인
