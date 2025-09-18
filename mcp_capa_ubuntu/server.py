#!/home/ubuntu/MCP_intent_ubuntu/mcp_capa_ubuntu/venv/bin/python
"""
CAPA Analysis MCP Server
- 단일 파일 또는 폴더 전체 바이너리 파일들에 대해 CAPA 분석 수행
- MCP_intent/analyzed/[세션이름] 폴더 구조로 CAPA_result.json 저장
- 모든 CAPA 기능 활용: 함수 주소 추출, MITRE 매핑 등
"""

import json
import subprocess
import os
import asyncio
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from typing import Any, Dict, List
import glob

from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio
import mcp.types as types

# ================================================
# 설정 (절대)
# ================================================
USER_PATH = Path("/home/ubuntu")
WATCH_FOLDER = USER_PATH / "malware-analyzer/watch-folder"
CAPA_PATH = USER_PATH / "capa_all"
CAPA_ENV = CAPA_PATH / "capa-env-312"
CAPA_RULES = CAPA_PATH / "capa-rules"
CAPA_SIGS = CAPA_PATH / "capa-sigs"
BASE_DIR = USER_PATH / "MCP_intent_ubuntu"
ANALYZED_DIR = BASE_DIR / "analyzed"

# 분석 세션 저장소
analysis_sessions: Dict[str, Dict[str, Any]] = {}

# ================================================
# CAPA 분석 함수
# ================================================
def run_capa_analysis(binary_path: Path) -> dict:
    """CAPA 분석 실행 - 모든 기능 활용"""
    cmd = [
        f"{CAPA_ENV}/bin/capa",
        "-r", str(CAPA_RULES),
        "-s", str(CAPA_SIGS),
        str(binary_path),
        "--json"
    ]
    env = os.environ.copy()
    env['PATH'] = f"{CAPA_ENV}/bin:{env['PATH']}"

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise Exception(f"CAPA 실행 실패: {result.stderr}")

    return json.loads(result.stdout)

def extract_function_addresses(capa_results: dict) -> List[Dict[str, Any]]:
    """CAPA 결과에서 함수 주소들 추출"""
    function_addresses = []

    if 'rules' in capa_results:
        for rule_name, rule_info in capa_results['rules'].items():
            if 'matches' in rule_info:
                for match in rule_info['matches']:
                    if isinstance(match, dict) and 'address' in match:
                        addr = match['address']
                        if isinstance(addr, int):
                            addr = hex(addr)
                        function_addresses.append({
                            "address": addr,
                            "rule": rule_name,
                            "type": match.get('type', 'function')
                        })

    return function_addresses

def extract_comprehensive_analysis(capa_results: dict, binary_path: Path) -> dict:
    """CAPA 결과에서 종합적인 분석 정보 추출"""
    # 기본 정보
    binary_stat = binary_path.stat()
    capabilities: List[str] = []
    mitre_mappings: List[Dict[str, str]] = []
    function_addresses = extract_function_addresses(capa_results)

    # 네임스페이스별 분류
    namespace_analysis = {}

    if 'rules' in capa_results:
        for rule_name, rule_info in capa_results['rules'].items():
            capabilities.append(rule_name)

            # MITRE ATT&CK 매핑
            if 'meta' in rule_info and 'attack' in rule_info['meta']:
                for attack in rule_info['meta']['attack']:
                    mitre_mappings.append({
                        "technique": attack.get('technique', ''),
                        "tactic": attack.get('tactic', ''),
                        "subtechnique": attack.get('subtechnique', ''),
                        "capability": rule_name
                    })

            # 네임스페이스 분석
            if 'meta' in rule_info and 'namespace' in rule_info['meta']:
                namespace = rule_info['meta']['namespace']
                if namespace not in namespace_analysis:
                    namespace_analysis[namespace] = []
                namespace_analysis[namespace].append(rule_name)

    # 위험도 분류 (더 정교한 키워드)
    high_risk_keywords = [
        'inject', 'hook', 'hide', 'rootkit', 'keylog', 'steal', 'bypass', 'disable',
        'anti-', 'evade', 'obfuscate', 'encrypt', 'pack', 'compress', 'delete'
    ]
    medium_risk_keywords = [
        'network', 'download', 'upload', 'registry', 'persistence', 'schedule',
        'service', 'driver', 'memory', 'process'
    ]

    high_risk_caps = []
    medium_risk_caps = []
    low_risk_caps = []

    for cap in capabilities:
        cap_lower = cap.lower()
        if any(keyword in cap_lower for keyword in high_risk_keywords):
            high_risk_caps.append(cap)
        elif any(keyword in cap_lower for keyword in medium_risk_keywords):
            medium_risk_caps.append(cap)
        else:
            low_risk_caps.append(cap)

    return {
        "binary_info": {
            "path": str(binary_path),
            "name": binary_path.name,
            "size": binary_stat.st_size,
            "modified": datetime.fromtimestamp(binary_stat.st_mtime).isoformat()
        },
        "analysis_summary": {
            "total_capabilities": len(capabilities),
            "high_risk_count": len(high_risk_caps),
            "medium_risk_count": len(medium_risk_caps),
            "low_risk_count": len(low_risk_caps),
            "mitre_techniques": len(mitre_mappings),
            "function_addresses": len(function_addresses)
        },
        "capabilities": {
            "all": capabilities,
            "high_risk": high_risk_caps,
            "medium_risk": medium_risk_caps,
            "low_risk": low_risk_caps
        },
        "mitre_attack": mitre_mappings,
        "function_addresses": function_addresses,
        "namespace_analysis": namespace_analysis,
        "full_capa_results": capa_results
    }

def find_executable_files(folder_path: Path, include_glob: str = "*", recursive: bool = True) -> List[Path]:
    """실행 파일 찾기"""
    executable_extensions = ['.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd']
    files = []

    if recursive:
        pattern = f"**/{include_glob}"
    else:
        pattern = include_glob

    for file_path in folder_path.glob(pattern):
        if file_path.is_file():
            # 확장자 확인 또는 실행 권한 확인
            if any(str(file_path).lower().endswith(ext) for ext in executable_extensions):
                files.append(file_path)
            elif os.access(file_path, os.X_OK):
                files.append(file_path)

    return files

# ================================================
# MCP 서버
# ================================================
server = Server("capa-analyzer")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    return [
        Tool(
            name="analyze_single",
            description="단일 바이너리 파일 CAPA 분석 후 analyzed/[세션이름]/CAPA_result.json 저장",
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "분석할 바이너리 파일 경로"},
                    "session_name": {"type": "string", "description": "세션 이름 (폴더명으로 사용)"}
                },
                "required": ["binary_path", "session_name"]
            }
        ),
        Tool(
            name="analyze_folder",
            description="지정 폴더 전체 실행파일들 CAPA 분석 후 각각 analyzed/[세션이름]/CAPA_result.json 저장",
            inputSchema={
                "type": "object",
                "properties": {
                    "folder_path": {"type": "string", "description": "분석할 폴더 경로"},
                    "base_session_name": {"type": "string", "description": "기본 세션 이름 (각 파일명이 추가됨)"}
                },
                "required": ["folder_path", "base_session_name"]
            }
        )
    ]

@server.call_tool()
async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> List[types.Content]:
    try:
        if name == "analyze_single":
            binary_path = Path(arguments["binary_path"]).expanduser().resolve()
            session_name = arguments["session_name"]

            if not binary_path.exists():
                return [TextContent(type="text", text=json.dumps({
                    "error": f"파일을 찾을 수 없습니다: {binary_path}"
                }, ensure_ascii=False, indent=2))]

            # analyzed/[세션이름] 폴더 생성
            session_dir = ANALYZED_DIR / session_name
            session_dir.mkdir(parents=True, exist_ok=True)

            # CAPA 분석 실행
            capa_results = run_capa_analysis(binary_path)
            comprehensive_analysis = extract_comprehensive_analysis(capa_results, binary_path)

            # 토큰 절약을 위해 full_capa_results 크기 체크 및 요약
            result_text = json.dumps(comprehensive_analysis, ensure_ascii=False)
            if len(result_text.encode('utf-8')) > 20000:  # 20KB로 제한
                # full_capa_results를 제거하고 요약만 저장
                comprehensive_analysis_summary = {k: v for k, v in comprehensive_analysis.items()
                                                 if k != "full_capa_results"}
                comprehensive_analysis_summary["note"] = "원본 CAPA 결과는 크기 제한으로 요약됨"
            else:
                comprehensive_analysis_summary = comprehensive_analysis

            # CAPA_result.json 저장
            with open(session_dir / "CAPA_result.json", 'w', encoding='utf-8') as f:
                json.dump(comprehensive_analysis, f, indent=2, ensure_ascii=False)

            # 세션 정보 저장
            session_id = str(uuid4())
            analysis_sessions[session_id] = {
                "session_name": session_name,
                "session_dir": str(session_dir),
                "binary_path": str(binary_path),
                "analysis_time": datetime.now().isoformat(),
                "status": "completed",
                "capabilities_count": comprehensive_analysis["analysis_summary"]["total_capabilities"],
                "high_risk_count": comprehensive_analysis["analysis_summary"]["high_risk_count"]
            }

            return [TextContent(type="text", text=json.dumps({
                "session_id": session_id,
                "session_name": session_name,
                "session_dir": str(session_dir),
                "saved_file": str(session_dir / "CAPA_result.json"),
                "analysis_summary": comprehensive_analysis["analysis_summary"],
                "status": "completed"
            }, ensure_ascii=False, indent=2))]

        elif name == "analyze_folder":
            folder_path = Path(arguments["folder_path"]).expanduser().resolve()
            base_session_name = arguments["base_session_name"]

            if not folder_path.exists() or not folder_path.is_dir():
                return [TextContent(type="text", text=json.dumps({
                    "error": f"폴더를 찾을 수 없습니다: {folder_path}"
                }, ensure_ascii=False, indent=2))]

            # 실행 파일 찾기
            executable_files = find_executable_files(folder_path, "*", True)

            if not executable_files:
                return [TextContent(type="text", text=json.dumps({
                    "error": "분석할 실행 파일을 찾을 수 없습니다"
                }, ensure_ascii=False, indent=2))]

            results = {
                "base_session_name": base_session_name,
                "folder_path": str(folder_path),
                "analysis_time": datetime.now().isoformat(),
                "total_files": len(executable_files),
                "processed_files": []
            }

            # 각 파일별로 분석 및 저장
            for binary_path in executable_files:
                try:
                    # 파일명 기반 세션 이름 생성
                    safe_filename = binary_path.stem.replace('.', '_').replace(' ', '_')
                    session_name = f"{base_session_name}_{safe_filename}"
                    session_dir = ANALYZED_DIR / session_name
                    session_dir.mkdir(parents=True, exist_ok=True)

                    # CAPA 분석 실행
                    capa_results = run_capa_analysis(binary_path)
                    comprehensive_analysis = extract_comprehensive_analysis(capa_results, binary_path)

                    # CAPA_result.json 저장
                    with open(session_dir / "CAPA_result.json", 'w', encoding='utf-8') as f:
                        json.dump(comprehensive_analysis, f, indent=2, ensure_ascii=False)

                    # 세션 정보 저장
                    session_id = str(uuid4())
                    analysis_sessions[session_id] = {
                        "session_name": session_name,
                        "session_dir": str(session_dir),
                        "binary_path": str(binary_path),
                        "analysis_time": datetime.now().isoformat(),
                        "status": "completed",
                        "capabilities_count": comprehensive_analysis["analysis_summary"]["total_capabilities"],
                        "high_risk_count": comprehensive_analysis["analysis_summary"]["high_risk_count"]
                    }

                    results["processed_files"].append({
                        "session_id": session_id,
                        "session_name": session_name,
                        "binary_path": str(binary_path),
                        "saved_file": str(session_dir / "CAPA_result.json"),
                        "summary": comprehensive_analysis["analysis_summary"],
                        "status": "success"
                    })

                except Exception as e:
                    results["processed_files"].append({
                        "binary_path": str(binary_path),
                        "error": str(e),
                        "status": "failed"
                    })

            return [TextContent(type="text", text=json.dumps(results, ensure_ascii=False, indent=2))]

        else:
            return [TextContent(type="text", text=json.dumps({
                "error": f"알 수 없는 도구: {name}"
            }, ensure_ascii=False))]

    except Exception as e:
        import traceback
        return [TextContent(type="text", text=json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "error_type": type(e).__name__
        }, ensure_ascii=False, indent=2))]

# ================================================
# 메인
# ================================================
async def main():
    from mcp.server.models import InitializationOptions
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="capa-analyzer",
                server_version="1.0.0",
                capabilities={"tools": {}}
            )
        )

if __name__ == "__main__":
    ANALYZED_DIR.mkdir(parents=True, exist_ok=True)
    asyncio.run(main())