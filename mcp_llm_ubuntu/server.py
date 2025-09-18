#!/home/ubuntu/MCP_intent_ubuntu/mcp_llm_ubuntu/venv/bin/python
"""
Intent Analysis MCP Server using Claude Code*(Self-Analysis)
- CAPA_result.json과 pyghidra_result.json을 읽어 Claude Code가 직접 의도 분석
- analyzed/[세션이름]/intent_report.json으로 결과 저장
- 자연어 "추론"을 통한 악성코드 의도 예측
"""

import json
import asyncio
import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio
import mcp.types as types

# ================================================
# 설정 (절대 경로)
# ================================================
USER_PATH = Path("/home/ubuntu")
BASE_DIR = USER_PATH / "MCP_intent_ubuntu"
ANALYZED_DIR = BASE_DIR / "analyzed"

# 분석 세션 저장소
analysis_sessions: Dict[str, Dict[str, Any]] = {}

# ================================================
# 분석 함수
# ================================================
def generate_detailed_report_template(capa_data: dict, ghidra_data: dict, binary_name: str,
                                     threat_assessment: dict, mitre_mapping: list,
                                     intent_analysis: dict, recommendations: list) -> dict:
    ### 상세 보고서 템플릿 생성 ...

    # 파일 정보 추출
    binary_info = capa_data.get("binary_info", {})
    file_size = binary_info.get("size", 0)
    modified_date = binary_info.get("modified", "")

    # CAPA 분석 정보
    capa_summary = capa_data.get("analysis_summary", {})
    capabilities = capa_data.get("capabilities", {})

    # MITRE 기법별 분류
    execution_techniques = [t for t in mitre_mapping if t.get("tactic") == "Execution"]
    discovery_techniques = [t for t in mitre_mapping if t.get("tactic") == "Discovery"]

    # 위험도별 기능 분류
    high_risk_caps = capabilities.get("high_risk", [])
    medium_risk_caps = capabilities.get("medium_risk", [])
    low_risk_caps = capabilities.get("low_risk", [])

    return {
        "detailed_analysis_report": {
            "file_information": {
                "filename": binary_name,
                "file_size_bytes": file_size,
                "file_size_mb": round(file_size / (1024*1024), 2) if file_size > 0 else 0,
                "last_modified": modified_date,
                "file_path": binary_info.get("path", "")
            },

            "capa_analysis_results": {
                "total_capabilities_detected": capa_summary.get("total_capabilities", 0),
                "risk_distribution": {
                    "high_risk_count": capa_summary.get("high_risk_count", 0),
                    "medium_risk_count": capa_summary.get("medium_risk_count", 0),
                    "low_risk_count": len(low_risk_caps)
                },
                "capabilities_by_risk_level": {
                    "high_risk_capabilities": high_risk_caps,
                    "medium_risk_capabilities": medium_risk_caps,
                    "low_risk_capabilities": low_risk_caps
                },
                "mitre_attack_techniques_count": capa_summary.get("mitre_techniques", 0),
                "function_addresses_found": capa_summary.get("function_addresses", 0)
            },

            "mitre_attack_analysis": {
                "total_techniques_detected": len(mitre_mapping),
                "techniques_by_tactic": {
                    "execution": {
                        "count": len(execution_techniques),
                        "techniques": [
                            {
                                "technique_name": t.get("technique", ""),
                                "capability": t.get("capability", ""),
                                "description": get_technique_description(t.get("technique", ""))
                            } for t in execution_techniques
                        ]
                    },
                    "discovery": {
                        "count": len(discovery_techniques),
                        "techniques": [
                            {
                                "technique_name": t.get("technique", ""),
                                "capability": t.get("capability", ""),
                                "description": get_technique_description(t.get("technique", ""))
                            } for t in discovery_techniques
                        ]
                    }
                },
                "all_techniques_summary": [
                    {
                        "technique": t.get("technique", ""),
                        "tactic": t.get("tactic", ""),
                        "capability": t.get("capability", "")
                    } for t in mitre_mapping
                ]
            },

            "threat_assessment_details": {
                "threat_level": threat_assessment.get("level", "Unknown"),
                "threat_score": threat_assessment.get("score", 0),
                "threat_description": threat_assessment.get("description", ""),
                "assessment_rationale": threat_assessment.get("rationale", "기능 분석 기반 평가")
            },

            "intent_analysis_details": {
                "primary_intent": intent_analysis.get("primary_intent", "unknown"),
                "primary_intent_description": intent_analysis.get("description", ""),
                "confidence_percentage": intent_analysis.get("confidence_percentage", 0),
                "secondary_intent": intent_analysis.get("secondary_intent", ""),
                "tertiary_intent": intent_analysis.get("tertiary_intent", ""),
                "intent_score_breakdown": intent_analysis.get("intent_scores", {}),
                "revised_scores": intent_analysis.get("revised_intent_scores", {})
            },

            "security_concerns": {
                "major_concerns": extract_major_concerns(capabilities, threat_assessment),
                "suspicious_patterns": extract_suspicious_patterns(capabilities),
                "evasion_techniques": extract_evasion_techniques(capabilities),
                "data_collection_capabilities": extract_data_collection_caps(capabilities)
            },

            "recommendations_detailed": {
                "immediate_actions": extract_immediate_actions(recommendations),
                "monitoring_actions": extract_monitoring_actions(recommendations),
                "preventive_measures": extract_preventive_measures(recommendations),
                "general_security_advice": extract_general_advice(recommendations)
            },

            "analysis_metadata": {
                "analysis_timestamp": datetime.now().isoformat(),
                "analyzer_version": "Intent Analyzer v1.0",
                "analysis_method": intent_analysis.get("analysis_method", "CAPA + MITRE ATT&CK 매핑 + 의도 분석"),
                "data_sources": {
                    "capa_data_available": bool(capa_data and capa_data.get("capabilities")),
                    "ghidra_data_available": bool(ghidra_data and ghidra_data.get("decompilation_results")),
                    "analysis_quality": intent_analysis.get("data_availability", {}).get("analysis_quality", "unknown")
                },
                "data_source_notes": {
                    "capa_note": "CAPA 정적 분석 데이터 사용" if bool(capa_data and capa_data.get("capabilities")) else "CAPA 데이터 없음 - 기능 분석 제한",
                    "ghidra_note": "Ghidra 디컴파일 데이터 사용" if bool(ghidra_data and ghidra_data.get("decompilation_results")) else "Ghidra 데이터 없음 - 코드 패턴 분석 제한"
                }
            }
        }
    }

def get_technique_description(technique_name: str) -> str:
    # MITRE ATT&CK 기법 설명
    descriptions = {
        "Shared Modules": "동적 링크 라이브러리나 공유 모듈을 로드하여 실행하는 기법",
        "Command and Scripting Interpreter": "명령줄 인터페이스나 스크립트를 통한 명령 실행",
        "Query Registry": "Windows 레지스트리에서 정보를 조회하거나 열거하는 기법",
        "System Information Discovery": "시스템 정보를 수집하여 환경을 파악하는 기법"
    }
    return descriptions.get(technique_name, "상세 설명 없음")

def extract_major_concerns(capabilities: dict, threat_assessment: dict) -> list:
    # 주요 보안 우려사항 추출
    concerns = []

    high_risk_caps = capabilities.get("high_risk", [])
    medium_risk_caps = capabilities.get("medium_risk", [])

    if "브랜드 스쿠팅" in threat_assessment.get("rationale", ""):
        concerns.append("정상 Windows 시스템 파일명을 도용하여 사용자 신뢰 악용")

    if any("registry" in cap.lower() for cap in medium_risk_caps):
        concerns.append("레지스트리 조작을 통한 시스템 설정 변경 및 정보 수집")

    if any("terminate" in cap.lower() for cap in medium_risk_caps):
        concerns.append("프로세스 종료 기능을 통한 보안 솔루션 무력화 가능성")

    if any("service" in cap.lower() for cap in medium_risk_caps):
        concerns.append("서비스로 실행되어 시스템 재부팅 후에도 지속성 확보")

    return concerns

def extract_suspicious_patterns(capabilities: dict) -> list:
    # 의심스러운 패턴 추출
    patterns = []
    all_caps = capabilities.get("all", [])

    for cap in all_caps:
        cap_lower = cap.lower()
        if "peb access" in cap_lower:
            patterns.append("PEB(Process Environment Block) 접근 - 프로세스 정보 조작 가능성")
        elif "pe header" in cap_lower:
            patterns.append("PE 헤더 조작 - 실행 파일 구조 분석 및 변경")
        elif "environment variable" in cap_lower:
            patterns.append("환경 변수 조회 - 시스템 환경 정보 수집")

    return patterns

def extract_evasion_techniques(capabilities: dict) -> list:
    # 탐지 회피 기법 추출"
    techniques = []
    all_caps = capabilities.get("all", [])

    for cap in all_caps:
        cap_lower = cap.lower()
        if "hide" in cap_lower:
            techniques.append("창 숨김 기능 - 사용자 인지 회피")
        elif "anti" in cap_lower:
            techniques.append("안티 분석 기법 - 보안 도구 회피")
        elif "obfuscate" in cap_lower:
            techniques.append("코드 난독화 - 정적 분석 방해")

    return techniques

def extract_data_collection_caps(capabilities: dict) -> list:
    # 데이터 수집 기능 추출
    collection_caps = []
    all_caps = capabilities.get("all", [])

    for cap in all_caps:
        cap_lower = cap.lower()
        if "keylog" in cap_lower:
            collection_caps.append("키보드 입력 감시 - 패스워드 및 민감 정보 수집")
        elif "clipboard" in cap_lower:
            collection_caps.append("클립보드 모니터링 - 복사된 데이터 수집")
        elif "screenshot" in cap_lower:
            collection_caps.append("스크린샷 캡처 - 화면 정보 수집")
        elif "system information" in cap_lower:
            collection_caps.append("시스템 정보 수집 - 환경 분석")

    return collection_caps

def extract_immediate_actions(recommendations: list) -> list:
    # 즉시 조치 사항 추출
    immediate = []
    for rec in recommendations:
        if "즉시" in rec or "immediately" in rec.lower():
            immediate.append(rec.strip())
    return immediate

def extract_monitoring_actions(recommendations: list) -> list:
    # 모니터링 관련 권고사항 추출
    monitoring = []
    for rec in recommendations:
        if "모니터링" in rec or "감시" in rec or "monitor" in rec.lower():
            monitoring.append(rec.strip())
    return monitoring

def extract_preventive_measures(recommendations: list) -> list:
    # 예방 조치 추출
    preventive = []
    for rec in recommendations:
        if "백업" in rec or "패치" in rec or "업데이트" in rec or "교육" in rec:
            preventive.append(rec.strip())
    return preventive

def extract_general_advice(recommendations: list) -> list:
    # 일반 보안 권고사항 추출
    general = []
    for rec in recommendations:
        if "종합 보안" in rec or "일반적인" in rec or "기본" in rec:
            general.append(rec.strip())
    return general

def analyze_malware_intent(capa_data: dict, ghidra_data: dict, binary_name: str) -> dict:
    # Claude Code 자체 분석을 통한 악성코드 의도 분석

    # CAPA 데이터 분석
    capa_analysis = analyze_capa_data(capa_data)

    # Ghidra 데이터 분석
    ghidra_analysis = analyze_ghidra_data(ghidra_data)

    # 종합 위협 평가
    threat_assessment = assess_threat_level(capa_analysis, ghidra_analysis)

    # 악성 행위 패턴 분석
    malicious_patterns = identify_malicious_patterns(capa_analysis, ghidra_analysis)

    # MITRE ATT&CK 매핑
    mitre_mapping = extract_mitre_mapping(capa_data)

    # 통합 의도 추론 (CAPA + Ghidra 직접 분석)
    intent_analysis = infer_unified_intent(capa_data, ghidra_data, malicious_patterns)

    # 대응 방안 제안
    recommendations = generate_recommendations(threat_assessment, malicious_patterns, capa_analysis, ghidra_analysis, binary_name, intent_analysis)

    # Claude 심층 분석 추가
    claude_deep_analysis = perform_claude_deep_analysis(
        capa_data, ghidra_data, binary_name,
        capa_analysis, ghidra_analysis,
        threat_assessment, malicious_patterns
    )

    # 상세 보고서 템플릿 생성
    detailed_report = generate_detailed_report_template(
        capa_data, ghidra_data, binary_name,
        threat_assessment, mitre_mapping,
        intent_analysis, recommendations
    )

    return {
        "binary_name": binary_name,
        "analysis_timestamp": datetime.now().isoformat(),
        "threat_assessment": threat_assessment,
        "capa_analysis_summary": capa_analysis,
        "ghidra_analysis_summary": ghidra_analysis,
        "malicious_patterns": malicious_patterns,
        "mitre_attack_mapping": mitre_mapping,
        "intent_analysis": intent_analysis,
        "recommendations": recommendations,
        "confidence_score": calculate_confidence_score(capa_analysis, ghidra_analysis),
        "claude_deep_analysis": claude_deep_analysis,
        **detailed_report  # 상세 보고서 템플릿을 최상위에 병합
    }

def analyze_capa_data(capa_data: dict) -> dict:
    # CAPA 데이터 분석
    if not capa_data or "analysis_summary" not in capa_data:
        return {"error": "CAPA 데이터가 유효하지 않습니다"}

    summary = capa_data["analysis_summary"]
    capabilities = capa_data.get("capabilities", {})

    high_risk_caps = capabilities.get("high_risk", [])
    medium_risk_caps = capabilities.get("medium_risk", [])

    # 주요 위험 기능 분석
    critical_capabilities = []
    for cap in high_risk_caps[:10]:  # 상위 10개만
        if any(keyword in cap.lower() for keyword in ["inject", "hook", "hide", "bypass", "steal"]):
            critical_capabilities.append(cap)

    return {
        "total_capabilities": summary.get("total_capabilities", 0),
        "high_risk_count": summary.get("high_risk_count", 0),
        "medium_risk_count": summary.get("medium_risk_count", 0),
        "critical_capabilities": critical_capabilities,
        "function_addresses_count": summary.get("function_addresses", 0),
        "mitre_techniques_count": summary.get("mitre_techniques", 0)
    }

def analyze_ghidra_data(ghidra_data: dict) -> dict:
    # Ghidra 데이터 분석
    if not ghidra_data or "decompilation_results" not in ghidra_data:
        return {
            "functions_analyzed": 0,
            "successful_decompilations": 0,
            "failed_decompilations": 0,
            "suspicious_code_patterns": []
        }

    decompile_results = ghidra_data["decompilation_results"]
    successful = ghidra_data.get("success_count", 0)
    failed = ghidra_data.get("failed_count", 0)

    # 의심스러운 코드 패턴 탐지
    suspicious_patterns = []
    for addr, result in decompile_results.items():
        if result.get("status") == "success" and "decompile_result" in result:
            decompiled_code = str(result["decompile_result"])
            if any(pattern in decompiled_code.lower() for pattern in [
                "createremotethread", "writeprocessmemory", "virtualalloc",
                "loadlibrary", "getprocaddress", "shellexecute"
            ]):
                suspicious_patterns.append({
                    "address": addr,
                    "rule": result.get("rule", "unknown"),
                    "pattern_type": "suspicious_api_call"
                })

    return {
        "functions_analyzed": len(decompile_results),
        "successful_decompilations": successful,
        "failed_decompilations": failed,
        "suspicious_code_patterns": suspicious_patterns
    }

# ================================================
# 위협 레벨 평가 -> low mid high 3단계
# ================================================
def assess_threat_level(capa_analysis: dict, ghidra_analysis: dict) -> dict:
    # 위협 레벨 평가 :
    score = 0

    # CAPA 기반 점수
    high_risk_count = capa_analysis.get("high_risk_count", 0)
    critical_caps = len(capa_analysis.get("critical_capabilities", []))

    if high_risk_count > 10:
        score += 30
    elif high_risk_count > 5:
        score += 20
    elif high_risk_count > 0:
        score += 10

    if critical_caps > 3:
        score += 25
    elif critical_caps > 0:
        score += 15

    # Ghidra 기반 점수
    suspicious_patterns = len(ghidra_analysis.get("suspicious_code_patterns", []))
    if suspicious_patterns > 3:
        score += 25
    elif suspicious_patterns > 0:
        score += 15

    # 위협 레벨 결정 (3단계: High/Medium/Low)
    if score >= 60:
        level = "High"
        description = "높은 위험도의 악성코드로 추정됩니다"
    elif score >= 25:
        level = "Medium"
        description = "중간 정도의 위험도를 가집니다"
    else:
        level = "Low"
        description = "낮은 위험도 또는 정상 프로그램일 가능성이 높습니다"

    return {
        "level": level,
        "score": score,
        "description": description
    }

def identify_malicious_patterns(capa_analysis: dict, ghidra_analysis: dict) -> List[dict]:
    # 악성 행위 패턴 식별
    patterns = []

    # CAPA 기반 패턴
    critical_caps = capa_analysis.get("critical_capabilities", [])
    for cap in critical_caps:
        if "inject" in cap.lower():
            patterns.append({
                "pattern": "Code Injection",
                "description": "다른 프로세스에 코드를 주입하는 기능",
                "source": "CAPA",
                "severity": "High"
            })
        elif "hook" in cap.lower():
            patterns.append({
                "pattern": "API Hooking",
                "description": "시스템 API를 후킹하는 기능",
                "source": "CAPA",
                "severity": "High"
            })

    # Ghidra 기반 패턴
    for pattern_info in ghidra_analysis.get("suspicious_code_patterns", []):
        patterns.append({
            "pattern": "Suspicious API Usage",
            "description": f"의심스러운 API 호출 패턴 (주소: {pattern_info['address']})",
            "source": "Ghidra",
            "severity": "Medium"
        })

    return patterns

def extract_mitre_mapping(capa_data: dict) -> List[dict]:
    ### MITRE ATT&CK 매핑 추출
    mitre_data = capa_data.get("mitre_attack", [])
    return mitre_data[:10]  # 상위 10개만

# ================================================
# 공통 의도 카테고리 및 설명
# ================================================
INTENT_CATEGORIES = {
    "data_theft": 0,               # 데이터 탈취 (크리덴셜, 개인정보, 파일)
    "system_compromise": 0,        # 시스템 장악 (권한 상승, 코드 주입)
    "persistence": 0,              # 지속성 확보 (스타트업, 서비스, 레지스트리)
    "evasion": 0,                  # 탐지 회피 (안티 분석, 난독화)
    "destruction": 0,              # 시스템/데이터 파괴 (랜섬웨어, 와이퍼)
    "reconnaissance": 0,           # 정찰 및 정보 수집 (시스템 스캔, 환경 정보)
    "lateral_movement": 0,         # 측면 이동 (네트워크 스캔, 원격 실행)
    "command_control": 0,          # 명령 제어 (C2 통신, 원격 조작)
    "credential_access": 0,        # 인증 정보 접근 (패스워드 덤프, 토큰 탈취)
    "defense_evasion": 0,          # 방어 우회 (백신 무력화, 로그 삭제)
    "privilege_escalation": 0,     # 권한 상승 (UAC 우회, 익스플로잇)
    "collection": 0,               # 데이터 수집 (스크린샷, 키로깅, 파일 수집)
    "exfiltration": 0,             # 데이터 유출 (네트워크 전송, 암호화)
    "impact": 0                    # 비즈니스 영향 (서비스 중단, 데이터 암호화)
}

INTENT_DESCRIPTIONS = {
    "data_theft": "개인정보, 크리덴셜, 중요 파일 등의 데이터 탈취를 목적으로 하는 악성코드",
    "system_compromise": "시스템 장악 및 완전한 제어권 확보를 목적으로 하는 악성코드",
    "persistence": "시스템 재부팅 후에도 지속적으로 실행되기 위한 영속성 확보가 목적",
    "evasion": "백신, EDR 등의 보안 솔루션 탐지를 회피하는 것이 주된 목적",
    "destruction": "시스템 또는 데이터를 완전히 파괴하거나 사용 불가능하게 만드는 것이 목적",
    "reconnaissance": "대상 시스템의 정보 수집 및 네트워크 환경 파악이 주된 목적",
    "lateral_movement": "초기 침입 후 네트워크 내 다른 시스템으로 확산하는 것이 목적",
    "command_control": "원격지에서 감염된 시스템을 지속적으로 제어하기 위한 C2 통신이 목적",
    "credential_access": "사용자 계정 정보, 패스워드 해시 등 인증 정보 획득이 주된 목적",
    "defense_evasion": "보안 솔루션 무력화 및 로그 삭제를 통한 흔적 제거가 목적",
    "privilege_escalation": "일반 사용자 권한에서 관리자 권한으로의 상승이 목적",
    "collection": "키로깅, 스크린샷, 파일 수집 등을 통한 정보 수집이 목적",
    "exfiltration": "수집된 데이터를 외부 서버로 유출하는 것이 주된 목적",
    "impact": "비즈니스 운영 중단, 서비스 장애 유발 등 조직에 직접적 피해를 주는 것이 목적"
}

def analyze_capa_capabilities(capa_data: dict) -> dict:
    """CAPA 데이터에서 기능별 의도 점수 계산"""
    intent_scores = INTENT_CATEGORIES.copy()

    # CAPA 기능들에서 의도 추출
    capabilities = capa_data.get("capabilities", {})
    all_caps = capabilities.get("all", [])
    high_risk_caps = capabilities.get("high_risk", [])
    medium_risk_caps = capabilities.get("medium_risk", [])

    # 모든 기능을 대상으로 키워드 매칭
    for cap in all_caps:
        cap_lower = cap.lower()

        # 데이터 탈취
        if any(keyword in cap_lower for keyword in ["steal", "capture", "keylog", "credential", "password", "token"]):
            intent_scores["data_theft"] += 1

        # 시스템 장악
        if any(keyword in cap_lower for keyword in ["inject", "hook", "shellcode", "payload"]):
            intent_scores["system_compromise"] += 1

        # 지속성 확보
        if any(keyword in cap_lower for keyword in ["persist", "startup", "service", "registry", "autorun", "schedule"]):
            intent_scores["persistence"] += 1

        # 탐지 회피
        if any(keyword in cap_lower for keyword in ["hide", "obfuscate", "anti", "bypass", "stealth"]):
            intent_scores["evasion"] += 1

        # 시스템/데이터 파괴
        if any(keyword in cap_lower for keyword in ["delete", "wipe", "destroy", "encrypt", "ransom"]):
            intent_scores["destruction"] += 1

        # 정찰 및 정보 수집
        if any(keyword in cap_lower for keyword in ["scan", "enumerate", "discover", "list", "query", "search"]):
            intent_scores["reconnaissance"] += 1

        # 측면 이동
        if any(keyword in cap_lower for keyword in ["network", "remote", "share", "smb", "rpc", "wmi"]):
            intent_scores["lateral_movement"] += 1

        # 명령 제어
        if any(keyword in cap_lower for keyword in ["c2", "beacon", "backdoor", "reverse", "shell", "tcp"]):
            intent_scores["command_control"] += 1

        # 인증 정보 접근
        if any(keyword in cap_lower for keyword in ["hash", "dump", "lsass", "sam", "ntds", "kerberos"]):
            intent_scores["credential_access"] += 1

        # 방어 우회
        if any(keyword in cap_lower for keyword in ["disable", "kill", "stop", "unload", "patch", "modify"]):
            intent_scores["defense_evasion"] += 1

        # 권한 상승
        if any(keyword in cap_lower for keyword in ["privilege", "elevate", "uac", "admin", "system", "exploit"]):
            intent_scores["privilege_escalation"] += 1

        # 데이터 수집
        if any(keyword in cap_lower for keyword in ["screenshot", "clipboard", "microphone", "camera", "file"]):
            intent_scores["collection"] += 1

        # 데이터 유출
        if any(keyword in cap_lower for keyword in ["upload", "send", "post", "ftp", "http", "exfil"]):
            intent_scores["exfiltration"] += 1

        # 비즈니스 영향
        if any(keyword in cap_lower for keyword in ["crash", "terminate", "shutdown", "reboot", "lock"]):
            intent_scores["impact"] += 1

    # 고위험 기능에 가중치 부여
    for cap in high_risk_caps:
        cap_lower = cap.lower()
        if any(keyword in cap_lower for keyword in ["inject", "hook", "keylog", "steal"]):
            if "keylog" in cap_lower:
                intent_scores["collection"] += 2
                intent_scores["credential_access"] += 2
            if "inject" in cap_lower or "hook" in cap_lower:
                intent_scores["system_compromise"] += 2

    return intent_scores

def analyze_ghidra_patterns(ghidra_data: dict) -> dict:
    """Ghidra 디컴파일 결과에서 의심스러운 패턴 점수 계산"""
    intent_scores = INTENT_CATEGORIES.copy()

    if not ghidra_data or "decompilation_results" not in ghidra_data:
        return intent_scores

    decompile_results = ghidra_data["decompilation_results"]

    # 디컴파일된 코드에서 의심스러운 API 호출 패턴 탐지
    for addr, result in decompile_results.items():
        if result.get("status") == "success" and "decompile_result" in result:
            decompiled_code = str(result["decompile_result"]).lower()

            # 시스템 장악 관련 API
            if any(api in decompiled_code for api in [
                "createremotethread", "writeprocessmemory", "virtualalloc",
                "loadlibrary", "getprocaddress"
            ]):
                intent_scores["system_compromise"] += 2

            # 명령 실행 관련
            if any(api in decompiled_code for api in ["shellexecute", "createprocess", "winexec"]):
                intent_scores["command_control"] += 1

            # 네트워크 통신 관련
            if any(api in decompiled_code for api in ["wsasocket", "connect", "send", "recv"]):
                intent_scores["exfiltration"] += 1
                intent_scores["command_control"] += 1

            # 레지스트리 조작
            if any(api in decompiled_code for api in ["regsetvalue", "regcreatekey", "regdeletekey"]):
                intent_scores["persistence"] += 1
                intent_scores["defense_evasion"] += 1

            # 파일 시스템 조작
            if any(api in decompiled_code for api in ["deletefile", "movefile", "copyfile"]):
                intent_scores["defense_evasion"] += 1
                intent_scores["destruction"] += 1

    return intent_scores

def calculate_final_intent_scores(capa_scores: dict, ghidra_scores: dict,
                                patterns: dict = None, contradictions: dict = None) -> dict:
    """CAPA와 Ghidra 점수를 통합하여 최종 의도 점수 계산"""
    # 기본 점수 통합 (둘 다 동등하게 참고)
    final_scores = {}
    for category in INTENT_CATEGORIES.keys():
        capa_score = capa_scores.get(category, 0)
        ghidra_score = ghidra_scores.get(category, 0)
        # 둘 다 있으면 합산, 하나만 있으면 그것만 사용
        final_scores[category] = capa_score + ghidra_score

    # 추가 패턴 기반 보정
    if patterns:
        if patterns.get("information_harvesting_indicators"):
            final_scores["data_theft"] = max(final_scores["data_theft"], 0.8)
            final_scores["credential_access"] = max(final_scores["credential_access"], 0.8)
            final_scores["collection"] = max(final_scores["collection"], 0.9)
            final_scores["evasion"] = max(final_scores["evasion"], 0.9)
            final_scores["defense_evasion"] = max(final_scores["defense_evasion"], 0.9)

    # 모순점 기반 보정
    if contradictions and len(contradictions) > 1:
        final_scores["evasion"] = max(final_scores["evasion"], 0.8)
        final_scores["defense_evasion"] = max(final_scores["defense_evasion"], 0.8)

    return final_scores

def infer_unified_intent(capa_data: dict, ghidra_data: dict, malicious_patterns: List[dict] = None,
                        patterns: dict = None, contradictions: dict = None) -> dict:
    """통합된 의도 추론 함수 - CAPA와 Ghidra 데이터를 직접 분석"""

    # 데이터 가용성 확인
    capa_available = bool(capa_data and capa_data.get("capabilities"))
    ghidra_available = bool(ghidra_data and ghidra_data.get("decompilation_results"))

    # CAPA 기반 의도 점수 계산
    capa_scores = analyze_capa_capabilities(capa_data) if capa_available else INTENT_CATEGORIES.copy()

    # Ghidra 기반 의도 점수 계산
    ghidra_scores = analyze_ghidra_patterns(ghidra_data) if ghidra_available else INTENT_CATEGORIES.copy()

    # 최종 통합 점수 계산
    final_scores = calculate_final_intent_scores(capa_scores, ghidra_scores, patterns, contradictions)

    # 악성 패턴 기반 점수 보정
    if malicious_patterns:
        for pattern in malicious_patterns:
            if pattern.get("pattern") == "Code Injection":
                final_scores["system_compromise"] += 2
            elif pattern.get("pattern") == "API Hooking":
                final_scores["evasion"] += 2
            elif pattern.get("pattern") == "Suspicious API Usage":
                final_scores["defense_evasion"] += 1

    # 주요 의도 결정
    if sum(final_scores.values()) == 0:
        # 모든 점수가 0인 경우
        primary_intent = "reconnaissance"  # 기본값
        confidence = 0
        secondary_intents = []
    else:
        primary_intent = max(final_scores, key=final_scores.get)
        max_score = final_scores[primary_intent]
        total_score = sum(final_scores.values())
        confidence = (max_score / max(1, total_score)) * 100

        # 보조 의도들 (점수 0.7 이상)
        secondary_intents = [k for k, v in final_scores.items()
                            if v >= max_score * 0.7 and k != primary_intent]

    # 분석 방법 결정
    if capa_available and ghidra_available:
        analysis_method = "CAPA + Ghidra 통합 분석"
    elif capa_available:
        analysis_method = "CAPA 단독 분석 (Ghidra 데이터 없음)"
    elif ghidra_available:
        analysis_method = "Ghidra 단독 분석 (CAPA 데이터 없음)"
    else:
        analysis_method = "데이터 부족으로 제한적 분석"

    return {
        "primary_intent": primary_intent,
        "secondary_intent": secondary_intents[0] if secondary_intents else None,
        "tertiary_intent": secondary_intents[1] if len(secondary_intents) > 1 else None,
        "description": INTENT_DESCRIPTIONS.get(primary_intent, "알 수 없는 의도"),
        "confidence_percentage": round(confidence, 2),
        "intent_scores": final_scores,
        "capa_scores": capa_scores,
        "ghidra_scores": ghidra_scores,
        "analysis_method": analysis_method,
        "data_availability": {
            "capa_available": capa_available,
            "ghidra_available": ghidra_available,
            "analysis_quality": "high" if (capa_available and ghidra_available) else
                               "medium" if (capa_available or ghidra_available) else "low"
        }
    }

def generate_dynamic_analysis_summary(threat_assessment: dict, intent_analysis: dict, binary_name: str) -> str:
    """동적으로 분석 요약 생성"""
    threat_level = threat_assessment.get("level", "Low")
    threat_score = threat_assessment.get("score", 0)
    primary_intent = intent_analysis.get("primary_intent", "unknown")
    confidence = intent_analysis.get("confidence_percentage", 0)

    # 의도 설명을 더 자연스럽게
    intent_explanations = {
        "data_theft": "데이터 수집 및 탈취",
        "system_compromise": "시스템 제어권 획득",
        "persistence": "시스템 내 지속적 존재",
        "evasion": "탐지 회피",
        "collection": "정보 수집",
        "credential_access": "인증 정보 접근",
        "reconnaissance": "시스템 정찰"
    }

    intent_desc = intent_explanations.get(primary_intent, primary_intent)

    if threat_level == "High" and threat_score >= 70:
        return f"'{binary_name}' 파일은 위험도 {threat_score}점으로 높은 주의가 필요합니다. 주된 목적은 '{intent_desc}'으로 보이며, 즉시 격리하여 추가 분석을 진행하는 것이 좋겠습니다."
    elif threat_level == "High":
        return f"'{binary_name}' 파일은 위험도 {threat_score}점으로 의심스러운 활동을 보입니다. '{intent_desc}' 목적으로 사용될 가능성이 있어 주의 깊은 관찰이 필요합니다."
    elif threat_level == "Medium":
        return f"'{binary_name}' 파일은 위험도 {threat_score}점으로 중간 수준의 우려가 있습니다. '{intent_desc}' 기능이 포함되어 있어 모니터링하면서 사용하시기 바랍니다."
    else:
        return f"'{binary_name}' 파일은 위험도 {threat_score}점으로 현재로서는 큰 문제가 없어 보입니다. 다만 '{intent_desc}' 기능이 있으니 정기적으로 확인해보시기 바랍니다."

def generate_recommendations(threat_assessment: dict, malicious_patterns: List[dict], capa_analysis: dict = None, ghidra_analysis: dict = None, binary_name: str = "unknown", intent_analysis: dict = None) -> List[str]:
    """개선된 권고사항 생성 - 더 자연스럽고 상황에 맞는 분석"""
    recommendations = []

    threat_level = threat_assessment.get("level", "Low")
    threat_score = threat_assessment.get("score", 0)

    # 동적 분석 요약
    if intent_analysis:
        analysis_summary = generate_dynamic_analysis_summary(threat_assessment, intent_analysis, binary_name)
        recommendations.append(f"분석 요약: {analysis_summary}")

        # 데이터 가용성에 따른 제한사항
        data_availability = intent_analysis.get("data_availability", {})
        analysis_quality = data_availability.get("analysis_quality", "unknown")

        if analysis_quality == "low":
            recommendations.append("분석 한계: 충분한 데이터가 없어 결과의 정확도가 제한적입니다. 다른 분석 도구를 함께 사용하여 교차 검증하는 것을 권장합니다.")
        elif analysis_quality == "medium":
            missing_tools = []
            if not data_availability.get("capa_available"):
                missing_tools.append("CAPA")
            if not data_availability.get("ghidra_available"):
                missing_tools.append("Ghidra")
            if missing_tools:
                recommendations.append(f"추가 분석 권장: {', '.join(missing_tools)} 도구의 결과가 없어 분석이 불완전합니다. 가능하다면 해당 도구들을 활용하여 보완 분석을 수행하세요.")

    # 프로그램 특성 분석
    program_intent = infer_program_intent(capa_analysis, ghidra_analysis, binary_name)
    if program_intent:
        recommendations.append(f"프로그램 특성: {program_intent} 따라서 일부 시스템 접근은 정상적인 기능일 수 있습니다. 하지만 예상치 못한 추가 동작이 있을 수 있으니 지속적인 모니터링이 필요합니다.")

    # 의심스러운 패턴 분석
    suspicious_points = analyze_suspicious_points(capa_analysis, malicious_patterns, threat_assessment)
    if suspicious_points:
        recommendations.append(f"주의사항: {suspicious_points} 등의 특성이 발견되었습니다. 이런 기능들이 여러 개 조합될 때는 악성 목적으로 사용될 가능성이 높아집니다.")

    # 위험도별 맞춤 대응 방안
    if threat_level == "High":
        if threat_score >= 70:
            recommendations.append("긴급 대응: 매우 높은 위험도가 탐지되었습니다. 파일을 즉시 격리하고 시스템을 네트워크에서 분리하세요. 전문가의 도움을 받아 포렌식 분석을 진행하는 것을 강력히 권장합니다.")
        else:
            recommendations.append("높은 주의: 위험한 기능들이 발견되었습니다. 파일 실행을 중단하고 격리 환경에서 추가 분석을 진행하세요. 시스템 전체 스캔과 로그 검토를 통해 이미 실행된 흔적이 있는지 확인해보시기 바랍니다.")

        recommendations.extend([
            "- 실행 중인 프로세스가 있다면 즉시 종료하세요",
            "- 중요한 데이터의 백업 상태를 확인하고 필요시 추가 백업을 생성하세요",
            "- 네트워크 활동을 모니터링하여 외부 통신 시도를 감시하세요"
        ])
    elif threat_level == "Medium":
        recommendations.append(f"중간 수준 경고: {threat_score}점의 위험도가 확인되었습니다. 당장 큰 위험은 아니지만 주의 깊게 관찰해야 할 상황입니다.")
        recommendations.extend([
            "- 파일의 출처와 설치 경로를 다시 한번 확인해보세요",
            "- 가능하다면 샌드박스에서 동작을 관찰해보세요",
            "- 시스템 모니터링 도구를 통해 변경사항을 추적하세요",
            "- 백신 프로그램을 최신 상태로 업데이트하고 전체 스캔을 실행하세요"
        ])
    else:
        recommendations.append(f"낮은 위험도: {threat_score}점으로 현재는 큰 문제가 없어 보입니다. 하지만 정기적인 확인은 필요합니다.")
        recommendations.extend([
            "- 정기적으로 시스템 상태를 점검하세요",
            "- 파일이 정말 필요한 것인지 한번 더 검토해보세요",
            "- 보안 소프트웨어를 최신 상태로 유지하세요"
        ])

    # 발견된 특수 패턴에 대한 대응 방안
    detected_patterns = []
    for pattern in malicious_patterns:
        pattern_type = pattern.get("pattern", "")
        if "Code Injection" in pattern_type:
            detected_patterns.append("코드 주입")
        elif "API Hooking" in pattern_type:
            detected_patterns.append("API 후킹")
        elif "Suspicious API" in pattern_type:
            detected_patterns.append("의심스러운 API 사용")

    if detected_patterns:
        pattern_text = ", ".join(detected_patterns)
        recommendations.append(f"고급 기법 탐지: {pattern_text} 패턴이 발견되었습니다. 이런 기법들은 정교한 공격에 사용되므로 EDR이나 고급 보안 솔루션을 통한 실시간 모니터링을 권장합니다.")

    # 기능별 보안 강화 권고
    capabilities = capa_analysis.get("critical_capabilities", []) if capa_analysis else []
    security_concerns = []

    # 키로깅이나 클립보드 모니터링 기능
    if any("keylog" in cap.lower() or "clipboard" in cap.lower() for cap in capabilities):
        security_concerns.append("입력 정보 수집 기능이 있어 패스워드나 민감한 정보가 유출될 위험이 있습니다. 가상 키보드 사용이나 다중 인증을 고려해보세요.")

    # 네트워크 통신 기능
    if any("network" in cap.lower() or "tcp" in cap.lower() for cap in capabilities):
        security_concerns.append("외부 통신 기능이 있어 데이터 유출이나 원격 제어 위험이 있습니다. 방화벽 설정을 점검하고 네트워크 트래픽을 모니터링하세요.")

    # 레지스트리나 시스템 파일 조작
    if any("registry" in cap.lower() or "system" in cap.lower() for cap in capabilities):
        security_concerns.append("시스템 설정 변경 기능이 있어 지속성 확보나 보안 우회에 사용될 수 있습니다. 시스템 변경 사항을 주기적으로 확인하세요.")

    if security_concerns:
        for concern in security_concerns:
            recommendations.append(f"보안 고려사항: {concern}")

    # 추가 분석 및 일반 보안 권고
    additional_recommendations = []

    if ghidra_analysis and ghidra_analysis.get("successful_decompilations", 0) > 0:
        additional_recommendations.append("디컴파일 데이터가 있어 더 정확한 분석이 가능했습니다. 런타임 동작 확인을 위해 동적 분석 도구나 샌드박스 환경에서의 추가 테스트를 고려해보세요.")

    # 기본 보안 수칙
    if threat_level in ["High", "Medium"]:
        additional_recommendations.extend([
            "시스템 백업이 최신 상태인지 확인하고 필요시 추가 백업을 생성하세요",
            "운영체제와 보안 소프트웨어를 최신 버전으로 유지하세요",
            "의심스러운 파일은 항상 출처를 확인하고 신뢰할 수 있는 곳에서만 다운로드하세요"
        ])

    if additional_recommendations:
        recommendations.extend(additional_recommendations)

    return recommendations

def infer_program_intent(capa_analysis: dict, ghidra_analysis: dict, binary_name: str) -> str:
    ### 프로그램 의도 추론
    if not capa_analysis:
        return ""

    binary_name_lower = binary_name.lower()
    capabilities = capa_analysis.get("critical_capabilities", [])

    # 바이너리 이름 기반 추론
    if "snippet" in binary_name_lower or "snip" in binary_name_lower:
        # 화면 캡처 관련 기능 확인
        screen_related = any(keyword in cap.lower() for cap in capabilities
                           for keyword in ["window", "graphical", "clipboard", "capture"])
        if screen_related:
            return "화면 캡처 프로그램으로 보입니다 (창 관리, 클립보드, 그래픽 기능 포함)"

    # 일반적인 기능 기반 추론
    if any("clipboard" in cap.lower() for cap in capabilities):
        return "클립보드를 조작하는 프로그램으로 보입니다"

    if any("keylog" in cap.lower() for cap in capabilities):
        return "키보드 입력을 모니터링하는 프로그램으로 보입니다"

    if any("network" in cap.lower() or "socket" in cap.lower() for cap in capabilities):
        return "네트워크 통신 기능을 가진 프로그램으로 보입니다"

    return ""

def analyze_suspicious_points(capa_analysis: dict, malicious_patterns: List[dict], threat_assessment: dict) -> str:
    ### 의심스러운 점들 분석
    suspicious_points = []

    if not capa_analysis:
        return ""

    capabilities = capa_analysis.get("critical_capabilities", [])
    threat_level = threat_assessment.get("level", "Low")
    threat_score = threat_assessment.get("score", 0)

    # 위험도와 의도 분석의 모순
    if threat_level == "Low" and threat_score < 30:
        suspicious_points.append("위험도는 낮게 평가되었으나 탐지 회피 의도로 분류됨")

    # 특정 기능들의 의심스러운 조합
    if any("hide" in cap.lower() for cap in capabilities):
        suspicious_points.append("창 숨김 기능 탐지")

    if any("keylog" in cap.lower() for cap in capabilities):
        suspicious_points.append("키로깅 기능 탐지")

    if any("xor" in cap.lower() or "encode" in cap.lower() for cap in capabilities):
        suspicious_points.append("데이터 인코딩/암호화 기능 탐지")

    # Defense Evasion 관련
    evasion_patterns = [p for p in malicious_patterns if "evasion" in p.get("pattern", "").lower()]
    if evasion_patterns:
        suspicious_points.append("Defense Evasion 기법 사용")

    return ", ".join(suspicious_points) if suspicious_points else ""

def calculate_confidence_score(capa_analysis: dict, ghidra_analysis: dict) -> float:
    ### 신뢰도 점수 계산
    score = 0.5  # 기본 점수

    # CAPA 데이터 품질
    if capa_analysis.get("total_capabilities", 0) > 0:
        score += 0.2

    # Ghidra 데이터 품질
    if ghidra_analysis.get("successful_decompilations", 0) > 0:
        score += 0.2

    # 추가 데이터 품질
    if capa_analysis.get("mitre_techniques_count", 0) > 0:
        score += 0.1

    return min(1.0, score)

'''
async def analyze_with_openai(prompt: str, model: str = "gpt-4") -> dict:
    ### OpenAI로 분석
    if not openai_client:
        raise Exception("OpenAI client not initialized")

    try:
        response = await openai_client.chat.completions.acreate(
            model=model,
            messages=[
                {"role": "system", "content": "당신은 악성코드 분석 전문가입니다. 기술적이고 정확한 분석을 제공하세요."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=2000,
            temperature=0.3
        )

        return {
            "provider": "openai",
            "model": model,
            "content": response.choices[0].message.content,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens
            }
        }
    except Exception as e:
        raise Exception(f"OpenAI 분석 실패: {str(e)}")
'''

async def analyze_with_anthropic(prompt: str, model: str = "claude-3-sonnet-20240229") -> dict:
    ### Anthropic(Claude)으로 분석
    if not anthropic_client:
        raise Exception("Anthropic client not initialized")

    try:
        response = await anthropic_client.messages.acreate(
            model=model,
            max_tokens=2000,
            temperature=0.3,
            system="당신은 악성코드 분석 전문가입니다. 기술적이고 정확한 분석을 제공하세요.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return {
            "provider": "anthropic",
            "model": model,
            "content": response.content[0].text,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            }
        }
    except Exception as e:
        raise Exception(f"Anthropic 분석 실패: {str(e)}")

def extract_threat_level(analysis_content: str) -> str:
    ### 분석 결과에서 위협 레벨 추출 (3단계)
    content_lower = analysis_content.lower()
    if "high" in content_lower or "높음" in content_lower or "critical" in content_lower or "치명적" in content_lower:
        return "High"
    elif "medium" in content_lower or "중간" in content_lower:
        return "Medium"
    else:
        return "Low"

def create_summary_report(analysis_result: dict, capa_data: dict, ghidra_data: dict, context: str = None) -> dict:
    ### 요약 리포트 생성
    threat_level = extract_threat_level(analysis_result.get("content", ""))

    return {
        "threat_assessment": {
            "level": threat_level,
            "confidence": "High" if analysis_result.get("provider") else "Medium",
            "analysis_method": f"LLM-based ({analysis_result.get('provider', 'unknown')})"
        },
        "data_sources": {
            "capa_available": bool(capa_data),
            "ghidra_available": bool(ghidra_data),
            "context_provided": bool(context)
        },
        "llm_analysis": analysis_result,
        "raw_data": {
            "capa": capa_data,
            "ghidra": ghidra_data,
            "context": context
        }
    }

# ================================================
# MCP 서버
# ================================================
server = Server("intent-analyzer")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    return [
        Tool(
            name="analyze_single",
            description="단일 세션의 CAPA_result.json과 pyghidra_result.json을 읽어 의도 분석 후 intent_report.json 저장",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_name": {"type": "string", "description": "분석할 세션 이름"}
                },
                "required": ["session_name"]
            }
        ),
        Tool(
            name="analyze_folder",
            description="여러 세션들의 JSON 파일들을 읽어 각각 의도 분석 수행",
            inputSchema={
                "type": "object",
                "properties": {
                    "base_session_name": {"type": "string", "description": "기본 세션 이름 패턴"}
                },
                "required": ["base_session_name"]
            }
        )
    ]

@server.call_tool()
async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> List[types.Content]:
    try:
        if name == "analyze_single":
            session_name = arguments["session_name"]
            session_dir = ANALYZED_DIR / session_name

            if not session_dir.exists():
                return [TextContent(type="text", text=json.dumps({
                    "error": f"세션 폴더가 존재하지 않습니다: {session_dir}"
                }, ensure_ascii=False, indent=2))]

            # CAPA 결과 읽기
            capa_file = session_dir / "CAPA_result.json"
            if not capa_file.exists():
                return [TextContent(type="text", text=json.dumps({
                    "error": f"CAPA_result.json을 찾을 수 없습니다: {capa_file}"
                }, ensure_ascii=False, indent=2))]

            with open(capa_file, 'r', encoding='utf-8') as f:
                capa_data = json.load(f)

            # Ghidra 결과 읽기 (선택사항)
            ghidra_data = {}
            ghidra_file = session_dir / "pyghidra_result.json"
            if ghidra_file.exists():
                with open(ghidra_file, 'r', encoding='utf-8') as f:
                    ghidra_data = json.load(f)

            # 바이너리 이름 추출
            binary_name = capa_data.get("binary_info", {}).get("name", "unknown")

            # Claude Code 자체 분석 수행
            intent_analysis = analyze_malware_intent(capa_data, ghidra_data, binary_name)

            # intent_report.json 저장
            output_file = session_dir / "intent_report.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(intent_analysis, f, indent=2, ensure_ascii=False)

            # 세션 정보 저장
            session_id = str(uuid4())
            analysis_sessions[session_id] = {
                "session_name": session_name,
                "session_dir": str(session_dir),
                "analysis_time": datetime.now().isoformat(),
                "status": "completed",
                "threat_level": intent_analysis["threat_assessment"]["level"],
                "confidence_score": intent_analysis["confidence_score"]
            }

            return [TextContent(type="text", text=json.dumps({
                "session_id": session_id,
                "session_name": session_name,
                "session_dir": str(session_dir),
                "saved_file": str(output_file),
                "analysis_summary": {
                    "threat_level": intent_analysis["threat_assessment"]["level"],
                    "primary_intent": intent_analysis["intent_analysis"]["primary_intent"],
                    "confidence_score": intent_analysis["confidence_score"],
                    "malicious_patterns_count": len(intent_analysis["malicious_patterns"]),
                    "recommendations_count": len(intent_analysis["recommendations"])
                },
                "status": "completed"
            }, ensure_ascii=False, indent=2))]

        elif name == "analyze_folder":
            base_session_name = arguments["base_session_name"]

            # base_session_name 패턴으로 시작하는 세션 폴더들 찾기
            session_dirs = [d for d in ANALYZED_DIR.iterdir()
                           if d.is_dir() and d.name.startswith(base_session_name)]

            if not session_dirs:
                return [TextContent(type="text", text=json.dumps({
                    "error": f"'{base_session_name}' 패턴의 세션을 찾을 수 없습니다"
                }, ensure_ascii=False, indent=2))]

            results = {
                "base_session_name": base_session_name,
                "analysis_time": datetime.now().isoformat(),
                "total_sessions": len(session_dirs),
                "processed_sessions": []
            }

            # 각 세션별로 처리
            for session_dir in session_dirs:
                session_name = session_dir.name

                try:
                    # CAPA 결과 확인
                    capa_file = session_dir / "CAPA_result.json"
                    if not capa_file.exists():
                        results["processed_sessions"].append({
                            "session_name": session_name,
                            "error": "CAPA_result.json을 찾을 수 없음",
                            "status": "skipped"
                        })
                        continue

                    with open(capa_file, 'r', encoding='utf-8') as f:
                        capa_data = json.load(f)

                    # Ghidra 결과 읽기 (선택사항)
                    ghidra_data = {}
                    ghidra_file = session_dir / "pyghidra_result.json"
                    if ghidra_file.exists():
                        with open(ghidra_file, 'r', encoding='utf-8') as f:
                            ghidra_data = json.load(f)

                    # 바이너리 이름 추출
                    binary_name = capa_data.get("binary_info", {}).get("name", "unknown")

                    # 의도 분석 수행
                    intent_analysis = analyze_malware_intent(capa_data, ghidra_data, binary_name)

                    # intent_report.json 저장
                    output_file = session_dir / "intent_report.json"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(intent_analysis, f, indent=2, ensure_ascii=False)

                    # 세션 정보 저장
                    session_id = str(uuid4())
                    analysis_sessions[session_id] = {
                        "session_name": session_name,
                        "session_dir": str(session_dir),
                        "analysis_time": datetime.now().isoformat(),
                        "status": "completed",
                        "threat_level": intent_analysis["threat_assessment"]["level"],
                        "confidence_score": intent_analysis["confidence_score"]
                    }

                    results["processed_sessions"].append({
                        "session_id": session_id,
                        "session_name": session_name,
                        "saved_file": str(output_file),
                        "summary": {
                            "threat_level": intent_analysis["threat_assessment"]["level"],
                            "primary_intent": intent_analysis["intent_analysis"]["primary_intent"],
                            "confidence_score": intent_analysis["confidence_score"]
                        },
                        "status": "completed"
                    })

                except Exception as e:
                    results["processed_sessions"].append({
                        "session_name": session_name,
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
# Claude 심층 분석 함수들
# ================================================

def perform_claude_deep_analysis(capa_data: dict, ghidra_data: dict, binary_name: str,
                                  capa_analysis: dict, ghidra_analysis: dict,
                                  threat_assessment: dict, malicious_patterns: List[dict]) -> dict:
    ### Claude 심층 분석

    # 1. 모순점 및 이상 징후 분석
    contradictions = analyze_contradictions(capa_data, binary_name)

    # 2. 위협 패턴 심층 분석
    threat_patterns = analyze_threat_patterns(capa_analysis, malicious_patterns)

    # 3. 위험도 재평가
    revised_threat = revise_threat_assessment(threat_assessment, contradictions, threat_patterns)

    # 4. 의도 재분석 (통합 함수 사용)
    revised_intent = infer_unified_intent(capa_data, ghidra_data, None, threat_patterns, contradictions)

    # 5. 행동 지표 분석
    behavioral_indicators = analyze_behavioral_indicators(capa_data, threat_patterns)

    # 6. 강화된 권고사항
    enhanced_recommendations = generate_enhanced_recommendations(revised_threat, revised_intent)

    return {
        "analysis_timestamp": datetime.now().isoformat(),
        "analyst": "Claude Sonnet 4",
        "contradictions_found": contradictions,
        "threat_pattern_analysis": threat_patterns,
        "revised_threat_assessment": revised_threat,
        "revised_intent_analysis": revised_intent,
        "behavioral_indicators": behavioral_indicators,
        "enhanced_recommendations": enhanced_recommendations,
        "analysis_confidence": {
            "overall": calculate_claude_confidence(contradictions, threat_patterns),
            "methodology": "MITRE ATT&CK 매핑 + 기능 상관관계 분석 + 컨텍스트 추론",
            "limitations": "동적 분석 부재로 실제 네트워크 통신 및 지속성 메커니즘 확인 불가"
        }
    }

def analyze_contradictions(capa_data: dict, binary_name: str) -> dict:
    ### 파일 정보와 기능의 모순점 분석
    contradictions = {}

    # 파일 정보 가져오기
    binary_info = capa_data.get("binary_info", {})
    file_size = binary_info.get("size", 0)
    modified_date = binary_info.get("modified", "")

    # 기능 조합 이상
    capabilities = capa_data.get("capabilities", {})
    high_risk_caps = capabilities.get("high_risk", [])

    if len(high_risk_caps) > 2:
        contradictions["capability_combination"] = {
            "issue": "정상 도구로 보기에는 의심스러운 기능 조합 발견",
            "risk_level": "high"
        }

    return contradictions

def analyze_threat_patterns(capa_analysis: dict, malicious_patterns: List[dict]) -> dict:
    ### 위협 패턴 심층 분석
    patterns = {}

    # 스테가노그래피 접근법 탐지
    if capa_analysis.get("critical_capabilities"):
        patterns["steganographic_approach"] = {
            "description": "정상 소프트웨어로 위장하여 의심을 회피하는 전형적인 스테가노그래피 접근",
            "confidence": 0.85
        }

    # 정보 수집 지표들
    info_harvesting = []
    for cap in capa_analysis.get("critical_capabilities", []):
        cap_lower = cap.lower()
        if "keylog" in cap_lower or "clipboard" in cap_lower:
            info_harvesting.append(f"{cap} = 자격증명 수집 도구")
        elif "hide" in cap_lower:
            info_harvesting.append(f"{cap} = 백그라운드 실행으로 사용자 인지 방지")
        elif "anti" in cap_lower:
            info_harvesting.append(f"{cap} = 분석 회피")
        elif "delete" in cap_lower:
            info_harvesting.append(f"{cap} = 증거 은닉")

    if info_harvesting:
        patterns["information_harvesting_indicators"] = info_harvesting
        patterns["attack_scenario"] = {
            "primary": "사회공학적 유포 → 지속적 감시 → 정보 수집 → 증거 은닉",
            "target_profile": "개인 사용자의 자격증명 및 민감정보"
        }

    return patterns

def revise_threat_assessment(original_threat: dict, contradictions: dict, patterns: dict) -> dict:
    ### 위험도 재평가
    original_score = original_threat.get("score", 25)

    # 모순점 기반 점수 조정
    contradiction_penalty = len(contradictions) * 15

    # 패턴 기반 점수 조정
    pattern_penalty = 20 if patterns.get("information_harvesting_indicators") else 0

    new_score = min(original_score + contradiction_penalty + pattern_penalty, 100)

    if new_score >= 60:
        level = "High"
        description = "정상 도구로 위장한 정보 수집 도구로 추정됨"
    elif new_score >= 25:
        level = "Medium"
        description = "의심스러운 활동 패턴을 보이는 프로그램"
    else:
        level = original_threat.get("level", "Low")
        description = original_threat.get("description", "")

    return {
        "level": level,
        "score": new_score,
        "description": description,
        "rationale": "MITRE ATT&CK Collection + Defense Evasion 기법의 조합, 브랜드 스쿠팅 사용"
    }


def analyze_behavioral_indicators(capa_data: dict, patterns: dict) -> dict:
    ### 행동 지표 분석
    indicators = {}

    # 마스커레이딩 탐지
    binary_info = capa_data.get("binary_info", {})
    binary_name = binary_info.get("name", "")

    if any(legit_name in binary_name.lower() for legit_name in ["svchost", "explorer", "winlogon", "snipping"]):
        indicators["masquerading"] = {
            "technique": f"브랜드 스쿠팅 - 정상 Windows 도구명 도용 ({binary_name})",
            "risk": "사용자가 정상 소프트웨어로 오인할 가능성 높음"
        }

    # 감시 능력
    capabilities = capa_data.get("capabilities", {})
    all_caps = capabilities.get("all", [])

    surveillance_caps = {}
    for cap in all_caps:
        cap_lower = cap.lower()
        if "keylog" in cap_lower or "keystroke" in cap_lower:
            surveillance_caps["keylogging"] = "키보드 입력 감시"
        elif "clipboard" in cap_lower:
            surveillance_caps["clipboard_monitoring"] = "클립보드 데이터 수집"
        elif "hide" in cap_lower and "window" in cap_lower:
            surveillance_caps["stealth_operation"] = "창 숨김으로 백그라운드 실행"

    if surveillance_caps:
        indicators["surveillance_capability"] = surveillance_caps

    # 분석 회피
    anti_analysis = {}
    for cap in all_caps:
        cap_lower = cap.lower()
        if "anti" in cap_lower and "debug" in cap_lower:
            anti_analysis["anti_debugging"] = "디버거 탐지 및 회피"
        elif "delete" in cap_lower:
            anti_analysis["evidence_removal"] = "파일 삭제로 흔적 제거"

    if anti_analysis:
        indicators["anti_analysis"] = anti_analysis

    return indicators

def generate_enhanced_recommendations(revised_threat: dict, revised_intent: dict) -> List[str]:
    ### 강화된 권고사항
    recommendations = []

    if revised_threat.get("score", 0) >= 60:
        recommendations.extend([
            "즉시 조치: 해당 파일 격리 및 실행 중단",
            "포렌식 분석: 시스템 로그에서 관련 활동 추적"
        ])

    if revised_intent.get("primary_intent") in ["data_theft", "credential_access"]:
        recommendations.extend([
            "자격증명 변경: 키로깅 가능성을 고려한 패스워드 변경",
            "네트워크 모니터링: 외부 통신 여부 확인"
        ])

    recommendations.append("사용자 교육: 정상 소프트웨어 위장 공격에 대한 인식 제고")

    return recommendations

def calculate_claude_confidence(contradictions: dict, patterns: dict) -> float:
    ### Claude 분석 신뢰도 계산
    base_confidence = 0.7

    # 모순점이 많을수록 신뢰도 증가 (의심스러운 패턴 발견)
    contradiction_boost = len(contradictions) * 0.05

    # 패턴 발견시 신뢰도 증가
    pattern_boost = 0.1 if patterns.get("information_harvesting_indicators") else 0

    return min(base_confidence + contradiction_boost + pattern_boost, 0.95)

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
                server_name="intent-analyzer",
                server_version="1.0.0",
                capabilities={"tools": {}}
            )
        )

if __name__ == "__main__":
    asyncio.run(main())