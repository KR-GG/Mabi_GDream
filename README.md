
# GDream

**GDream**은 *마비노기 모바일*에서 궁수 직업의 전투 데이터를 실시간으로 분석하고 시각화하는 <strong>**딜미터기**(DPS Meter)</strong>입니다.  
게임 패킷을 분석해 WebSocket으로 전송하고, 별도의 HTML 인터페이스에서 실시간으로 확인할 수 있습니다.

---

## 🎯 주요 특징

- **궁수 직업 전용** 실시간 전투 로그 분석
- **WebSocket 기반 전송** + 브라우저 기반 시각화
- **Brotli 압축 해제**, Skill/Damage 플래그 파싱
- **실행 파일 단일 배포** (`capture.exe`)

---

## 🚀 사용법

0. [Npcap](https://nmap.org/npcap/) 설치 [🔗 Npcap 설치 페이지](https://nmap.org/npcap/)
> 설치할 때, **"Install Npcap in WinPcap API-compatible Mode"** 옵션을 꼭 체크해주세요.
1. `capture.exe` 실행  
2. 파일 목록에서 `stats.html` 더블 클릭  
3. 실시간 딜로그를 브라우저에서 확인

> ⚠ 프로그램 실행 시 방화벽 접근 권한 요청이 뜰 수 있습니다. "허용"해 주세요.

---

### ❗ WebSocket 연결이 계속 반복되는 경우?

- `stats.html` 파일을 새로고침(F5)하거나
- 브라우저 탭을 닫고 다시 열어주세요.
- 그래도 문제가 계속된다면 `capture.exe`를 재실행해 보세요.

---

## 📁 구성 파일

| 파일명          | 설명                          |
|----------------|------------------------------|
| `capture.exe`  | 패킷 분석 및 WebSocket 서버 실행|
| `stats.html`   | 클라이언트 뷰어 (웹 페이지)      |
| `mdm2.log`     | 분석 로그 (자동 생성)           |

---

## ⚙️ 요구사항

- Windows 10 이상
- 가상 머신 환경에서 돌리길 권장
- 관리자 권한 실행 권장

---

## ⚠️ 제한 사항

- 현재 **궁수 계열 직업만 지원**
- 도트딜 & 어비스 룬 관련 정확히 동작하는지 확인 불가


⚠️ 일부 백신이 이 실행 파일을 잘못된 악성코드로 인식할 수 있습니다.  
이는 패킷 분석 및 네트워크 관련 기능, 그리고 압축된 구조 때문입니다.

- [🔗 VirusTotal 결과 보기](https://www.virustotal.com/gui/file/96e00a75d4a614f9c5594698b2f465891253b263aab1010f9f041fbe6e3e6a5a?nocache=1)
- 본 프로젝트는 Python 기반 오픈소스입니다. 누구나 소스를 확인하고 실행파일을 직접 빌드할 수 있습니다.
- 실행 파일은 아래 명령어로 재현할 수 있습니다:
> nuitka --standalone --onefile --msvc=latest --include-package=websockets --noinclude-pytest-mode=nofollow --remove-output capture.py
- 의심된다면 직접 소스를 확인하거나 Python에서 실행해보실 수 있습니다.

🛡 사용 중 백신에 의해 삭제될 경우, 예외 등록 후 사용해주세요.

---

## 📄 라이선스

본 프로젝트는 MIT 라이선스를 따릅니다.  
개인적인 용도 외의 무단 배포/수정은 제한될 수 있습니다.

---

## 🙋‍♂️ 개발자 노트

- 프로젝트명: `GDream`  
- 개발자: KR-GG  
- 문의: GitHub Issues 또는 DM


