# Hydra-bane

[English](README.md) · **한국어**

**AI 에이전트에게 윈도우 정리를 맡기세요. 내가 승인하기 전에는 아무것도 바뀌지 않고, 옮긴 것은 되돌릴 수 있습니다.**

Windows 10/11용 디스크 정리 CLI이자 Claude Code 플러그인입니다. 에이전트가 먼저 스캔하고, 봉인된 계획을 만들어 무엇을 건드릴지 그대로 보여 준 다음, 내가 "예"라고 할 때까지 기다립니다. 바꾼 것은 전부 영수증으로 남습니다.

[![npm](https://img.shields.io/npm/v/hydra-bane?style=flat-square)](https://www.npmjs.com/package/hydra-bane)
[![CI](https://img.shields.io/github/actions/workflow/status/hydra-bane/hydra-bane/ci.yml?branch=main&style=flat-square&label=CI%20(Windows))](https://github.com/hydra-bane/hydra-bane/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/hydra-bane/hydra-bane/blob/main/LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?style=flat-square)

![scan, plan, y/N 확인 후 apply, 그리고 undo](assets/demo.gif)

<sub>일회용 샌드박스 프로필에서 실제로 실행한 화면을 편집 없이 녹화했습니다(실제 파일은 건드리지 않음). 녹화 스크립트는 <code>scripts/demo/</code>에 있습니다.</sub>

> [!NOTE]
> **v0.2**에서 [Atlas](#atlas-나라별-원치-않는-프로그램)(나라별 번들·잘 안 지워지는 프로그램 목록), 관리자 권한 정리, 개발·AI 캐시 10종, 읽기 전용 MCP 서버, 하드링크를 반영한 용량 계산이 추가됐습니다. 위협 증거 점검은 아직 [로드맵](#로드맵)에 있습니다.

## 빠르게 시작하기

Windows 10/11과 Node.js 22.18 이상이 필요합니다. 스캔에는 관리자 권한이 필요 없습니다.

```powershell
npx hydra-bane scan        # read-only: shows what could be reclaimed, changes nothing
```

**Claude Code 플러그인**(스킬, MCP 서버, 승인 훅 포함). 아래 두 줄은 따로따로 보내야 합니다.

```
/plugin marketplace add hydra-bane/hydra-bane
```
```
/plugin install hydra-bane@hydra-bane
```

그다음 이렇게 말하면 됩니다: *"hydra-bane으로 디스크 공간 좀 확보해 줘."* 다른 에이전트는 [지원 환경](#지원-환경)을 보세요.

## 스캔 결과 예시

개발자 PC에서 실제로 나온 출력입니다(v0.1).

```
> hydra-bane scan
Found 9.82 GB reclaimable. Nothing was changed.
  TEMP                 0.27 GB  Temp files older than 24h (477 entries)
  NPM                  0.35 GB  npm cache
  PNPM                 0.49 GB  pnpm store (prune removes unreferenced packages: up to this size)
  UV                   7.82 GB  uv cache (prune removes unused entries: up to this size)
  BROWSER-CHROME       0.73 GB  Chrome cache (cookies, logins and history are not touched)
  SHADER-NVIDIA-DX     0.09 GB  GPU shader cache NVIDIA\DXCache (rebuilt by games; first launch may stutter)
  DUMPS                0.05 GB  Application crash dumps (10 file(s); keep them if a developer asked for them)

Next: hydra-bane plan --select <ids>   (or --all-safe)
```

실행 전에 뜨는 승인 창은 이렇게 생겼습니다. Claude Code의 권한 우회(bypass-permissions) 모드에서도 뜹니다.

```
Hydra-bane will apply plan mui6uyrt780161d8 (8b6e44b8):
- PIP 70 MB: runs "pip cache purge" on c:\users\you\appdata\local\pip\cache (re-downloadable, not undoable)
```

## 동작 방식

```
scan  ->  plan  ->  you approve  ->  apply  ->  receipt  ->  undo (7 days)
```

1. **`scan`** 은 정리 후보를 찾기만 하고 아무것도 바꾸지 않습니다.
2. **`plan --select TEMP,NPM`** 은 고른 항목을 봉인합니다. 해시로 고정되고, 내 계정과 PC에 묶이며, 24시간 동안만 유효합니다. 내가 읽은 뒤에 항목이 늘어날 수 없습니다.
3. **`apply <plan-id>`** 는 확인 없이는 실행되지 않습니다. 에이전트가 계획을 보여 주고 물어보며, 터미널에서는 y/N으로 묻습니다. 스크립트에서 쓰려면 `--yes`를 붙여야 합니다.
4. 모든 변경은 실행되기 **전에** 해시 체인 영수증 원장에 먼저 기록됩니다.
5. **`undo <tx>`** 는 격리해 둔 항목을 제자리로 돌려놓습니다. 7일이 지난 격리 항목은 `scan`에 `Q-…`로 나타나고, 비울지는 내가 정합니다. 자동으로 비우는 일은 없습니다.

## 정리 대상

| 대상 | 처리 방식 | 되돌릴 수 있나요? |
|---|---|---|
| 24시간 넘은 임시 파일 | 격리함으로 이동 | 예, 7일 동안 `undo` |
| 앱 크래시 덤프 | 격리함으로 이동 | 예, 7일 동안 `undo` |
| 30일 넘게 손대지 않았고 git이 무시하는 `node_modules` / Rust `target` (`~/source`, `~/dev`, `~/projects`, `~/repos` 또는 `--root <dir>` 아래) | 격리함으로 이동 | 예, 7일 동안 `undo` |
| npm, pnpm, pip, uv, yarn, bun, conda, poetry, Go, NuGet 캐시 | 각 도구의 공식 정리 명령 실행 (예: `npm cache clean --force`, `go clean -cache`, `dotnet nuget locals … --clear`) | 필요할 때 다시 받아짐 |
| Cargo 레지스트리, 오래된 Gradle 버전, 오래 안 쓴 Maven 아티팩트, Hugging Face 모델 | 삭제 | 필요할 때 다시 받아짐 |
| Ollama 모델 | `ollama rm <model>` 실행. 다른 모델과 공유하는 레이어는 남김 | `ollama pull` |
| Chrome, Edge, Brave, Firefox 캐시 | 캐시 폴더만 삭제. 브라우저가 켜져 있으면 거부 | 브라우저가 다시 만듦 |
| GPU 셰이더 캐시 | 삭제 | 게임이 다시 만듦 |
| 관리자 항목: Windows 업데이트 다운로드, 배달 최적화 캐시, 오래된 시스템 Temp, 메모리 덤프, 대체된 구성 요소(DISM), 최대 절전 파일 | `apply`는 건너뜀. `apply-admin`이 UAC 확인 후 관리자 전용 도우미로 실행 | 불가(영구) |
| WSL 가상 디스크 | `wsl --manage <distro> --set-sparse true`로 디스크가 빈 공간을 스스로 돌려주게 함 | 같은 명령으로 되돌림 |
| `Windows.old`, Docker Desktop 디스크 | 보고만 하고 공식 제거 방법을 안내 | 해당 없음 |

하드링크된 파일은 한 번만 세기 때문에 pnpm 저장소 같은 캐시의 용량이 부풀려지지 않습니다. 어떤 항목인지 모르겠다면 `hydra-bane explain <id>`가 왜 안전한지, 지우면 어떻게 되는지 알려 줍니다.

## Atlas: 나라별 원치 않는 프로그램

[Atlas](https://github.com/hydra-bane/atlas)는 커뮤니티가 나라별로 관리하는 번들·잘 안 지워지는 프로그램 목록입니다(데이터는 CC BY-SA 4.0). 첫 목록은 한국·미국 항목 7개이며, 모두 KISA 보안 공지, 미국 FTC, 보안 연구 같은 공개 출처가 붙어 있습니다. `hydra-bane atlas update`로 서명된 목록을 받으면, `scan`이 설치된 프로그램 중 Atlas 항목과 일치하는 것을 알려 줍니다. 은행 보안 프로그램처럼 한국 사용자에게 익숙한 것들도 이 목록의 대상입니다.

Atlas는 판정이 아니라 사실만 보여 줍니다. 일치한 프로그램마다 다음을 표시합니다.

- **무엇인지**: 출처가 붙은 중립적인 한 문장.
- **내 PC에서 하는 일**: 스캔할 때 읽기 전용으로 직접 측정합니다. 설치한 신뢰할 수 있는 루트 인증서, 열어 둔 포트와 다른 컴퓨터에서 접속할 수 있는지, Windows와 함께 시작하는 서비스.
- **제3자 보안 공지(KISA, NVD, CISA 등)**: 날짜와 링크를 붙여 인용하고, 공지의 버전 범위에 내 버전이 들어갈 때만 "내 버전 해당"으로 표시합니다. 예전 버전 대상 공지에는 내 버전이 더 새것이라고 적습니다.

Hydra-bane은 프로그램을 판정하지 않습니다. 남길지는 사용자가 정합니다.

- **제거는 제조사의 언인스톨러로만 합니다.** 레지스트리에 적힌 명령줄을 그대로 실행하지 않습니다. 언인스톨러는 Atlas 항목이 지정한 파일이어야 하고, 항목에 고정된 인증서로 서명돼 있어야 하며, 인자가 프로그램 폴더 밖을 가리키면 안 됩니다. 하나라도 어긋나면 거부합니다.
- **언인스톨러를 검증할 수 없으면 보고만 합니다.** 무엇을 찾았는지 알려 주고 설정 > 앱으로 안내합니다.

Atlas에 없는 프로그램을 발견했다면? 에이전트에게 지워 달라고 할 때 Hydra-bane이 제보할지 물어봅니다. 올라갈 내용(이름, 게시자, 코드 서명자, 파일 해시, `%VAR%` 기준 상대 경로)을 먼저 그대로 보여 줍니다. 사용자 이름, PC 이름, 실제 경로는 절대 들어가지 않고, "예"라고 하기 전에는 아무것도 전송되지 않습니다. 봇이 제보를 프로그램마다 하나의 후보 PR로 모으고, 메인테이너가 검토합니다.

### 어떤 프로그램이든 제거하기

Atlas에 없는 프로그램도 지울 수 있습니다. `hydra-bane uninstall <program-id>`(id는 `programs`에서 확인)가 그 프로그램의 언인스톨러를 실행하는 한 항목짜리 계획을 봉인하고, 승인하면 `apply`가 실행합니다. 레지스트리 값은 명령이 아니라 데이터로만 다룹니다. Windows Installer 제품이면 Hydra-bane이 `msiexec /x {제품 코드}`를 직접 만들고, 그 밖에는 언인스톨러에 그 프로그램 게시자의 유효한 서명이 있거나, 모든 사용자용으로 설치돼 관리자만 바꿀 수 있는 폴더에 있어야 실행합니다. 셸·스크립트 호스트나 프로그램 폴더 밖을 가리키는 인수는 거부하고, 실행 직전에 모든 검사를 다시 합니다. 승인 창에는 실행할 명령줄이 그대로 표시됩니다. 조건을 못 채우면 설정 > 앱에서 지우는 방법만 알려 줍니다.

제거한 뒤에는 `hydra-bane scan --only leftovers`가 그 프로그램이 남긴 것을 찾습니다. 대상은 AppData에서 이름이 정확히 같은 폴더, 가리키는 곳이 사라진 바로가기, `HKCU\Software` 아래의 키입니다. 폴더는 격리함으로 옮기고 레지스트리 키는 내보낸 뒤 지우므로, `undo`로 둘 다 되돌릴 수 있습니다. 문서나 git 저장소가 든 폴더, 모든 사용자 공용 폴더는 보고만 합니다. Hydra-bane이 직접 지운 프로그램만 살펴보며, AppData 전체를 추측으로 뒤지지 않습니다.

## 그냥 에이전트한테 `rm -rf` 시키면 안 되나요?

에이전트는 이미 파일을 지울 수 있습니다. 문제는 무엇을 지웠는지 사라진 뒤에야 안다는 점입니다.

| | 에이전트가 즉석에서 정리 | Hydra-bane |
|---|---|---|
| 무엇을 건드리나 | 조합한 명령에 걸리는 것 전부 | 크기와 함께 먼저 읽어 본 목록 |
| 범위가 커질 위험 | 다음 명령이 더 멀리 갈 수 있음 | 계획이 봉인됨. 바꾸려면 새 계획 |
| 누가 승인하나 | 에이전트 (자동 승인 모드라면 더더욱) | 나. 항목을 전부 적은 확인 창으로 |
| 실수하면 | 영구 손실 | 사용자 파일은 삭제가 아니라 격리 |
| 기록 | 스크롤백에 남아 있다면 | 변경마다 위변조를 알 수 있는 영수증 |

## 다른 도구와 비교

Hydra-bane이 윈도우 최초의 정리 도구는 아니고, 아래 도구들을 대체하려는 것도 아닙니다. 각 칸은 해당 프로젝트의 README와 공식 문서에서 2026-09-26에 확인한 내용입니다. "—"는 문서에서 관련 내용을 찾지 못했다는 뜻입니다.

| | Hydra-bane | [Mole](https://github.com/tw93/Mole/tree/windows) (Windows 브랜치) | [BleachBit](https://www.bleachbit.org/) | [winutil](https://github.com/ChrisTitusTech/winutil) | [Bulk Crap Uninstaller](https://github.com/BCUninstaller/Bulk-Crap-Uninstaller) | 에이전트 + 셸 |
|---|---|---|---|---|---|---|
| 주 용도 | 에이전트가 수행하는 디스크 정리와 원치 않는 프로그램 제거 | 윈도우 정리·최적화, 앱 제거 | 디스크 공간 확보, 개인정보 흔적 정리 | 앱 설치, 트윅·디블로트, 윈도우 업데이트 설정 | 여러 프로그램 일괄 제거 | 무엇이든 |
| AI 에이전트용 설계 (JSON 출력, 플러그인, MCP) | 예 | 아니요 | 아니요 | 아니요 | 아니요 (XML 내보내기만) | 해당 없음 |
| 변경 전 미리보기 | `scan`·`plan`은 읽기 전용 | clean·optimize에 `--dry-run`, uninstall은 y/N 확인 | 미리보기 (GUI와 `--preview`) | — | 확인 창, 잔재 목록, 선택형 시뮬레이션 | 에이전트가 하기 나름 |
| 되돌리기 | 격리 + 7일간 `undo` (캐시는 대신 다시 받음) | 없음. 삭제는 영구적 | 없음 | "Undo Selected Tweaks", 선택형 복원 지점 | 선택형 복원 지점, 잔재는 휴지통으로 | 기본 제공 없음 |
| 제거 후 잔재 정리 | 예. 직접 제거한 프로그램에 한해 이름이 정확히 같은 폴더, 끊어진 바로가기, 사용자 레지스트리 키를 정리하며 모두 되돌릴 수 있음 | 예 | 해당 없음 (언인스톨러 아님) | — | 예, 항목마다 신뢰도 표시 | 에이전트가 짠 대로 |
| 나라별 번들 소프트웨어 목록 | Atlas (CC BY-SA 4.0) | — | — | — | — | 없음 |
| 상태 | 초기 (v0.2) | "Experimental", 프리릴리스 빌드 | 안정 (6.0.4, 2026년 9월) | 활발 (26.08.19 릴리스) | 활발 (6.3, 2026년 9월) | 해당 없음 |
| 라이선스 | Apache-2.0 | MIT (Windows 브랜치) | GPL-3.0+ | MIT | Apache-2.0 | 해당 없음 |

Mole은 macOS에서 훌륭한 도구입니다. Mac을 쓴다면 Mole을 쓰세요. Hydra-bane은 Mole의 명령 구성을 참고했지만 포팅판은 아닙니다. BleachBit, winutil, BCU는 각자 맡은 일을 지금의 Hydra-bane보다 훨씬 넓게 해내는 성숙한 도구입니다. Hydra-bane이 더하는 것은 AI 에이전트에게 필요한 부분, 즉 봉인된 계획, 사람의 승인, 영수증, 되돌리기입니다. 표에 틀린 내용이 있으면 이슈로 알려 주세요.

## 안전 설계

- **경로 가드.** 드라이브 루트, 사용자 프로필, 알려진 폴더(바탕화면, 문서, OneDrive 등)와 이들을 품은 상위 폴더는 거부합니다. `.git`, `.ssh`, `.gnupg`를 지나는 경로도 거부합니다. 모호한 경로(`/c/…`, `..`, UNC, 8.3 짧은 이름, 대체 데이터 스트림)와 정션 우회도 막습니다. 무작위 경로 1만 개로 테스트했습니다.
- **삭제 대신 격리.** 항목을 같은 볼륨 안의 격리 폴더로 통째로 옮깁니다. 이 폴더는 상속이 끊겨 있고 실행이 금지돼 있습니다. 복원할 때 기존 파일을 덮어쓰지 않으며, SHA-256으로 변조를 감지합니다(256MB 이하 파일).
- **승인 훅.** Claude Code 플러그인은 `hydra-bane apply`나 `undo` 전에 반드시 사용자에게 묻게 하고, 확인 창에 무엇이 실행될지 적어 줍니다. 어떤 명령이든 드라이브나 프로필을 재귀 삭제하려 하면 막습니다. Claude Code 2.1.283의 권한 우회 모드에서 확인했습니다.
- **MCP 도구로는 PC를 바꿀 수 없습니다.** MCP 서버로는 스캔, 설명, 용량 분석, 봉인된 계획 작성(Hydra-bane 자체 폴더의 파일), 영수증 검증만 할 수 있습니다. apply·undo 도구는 없습니다. 적용은 사람의 몫입니다.
- **관리자 작업은 관리자 전용 폴더에서.** 권한 상승이 필요한 단계는 관리자만 쓸 수 있는 폴더에 복사된 도우미가 실행하며, 복사 전에 npm 레지스트리의 해시와 대조합니다. UAC 창에 계획 해시가 표시되고, 도우미는 호출한 쪽을 믿지 않고 계획을 처음부터 다시 검사합니다.
- **영수증.** 해시 체인 원장이라 수정·삭제·순서 바꿈이 드러납니다. `hydra-bane ledger`로 검증할 수 있습니다.

### 한계

- Claude Code 플러그인의 훅이 없으면, 자동 승인 모드의 에이전트가 스스로 `--yes`를 붙일 수 있습니다. `hydra-bane apply`에는 승인을 켜 두세요.
- 도구 자체 명령으로 비운 캐시, 제거한 프로그램, 비운 격리함은 되돌릴 수 없습니다.
- pnpm, uv, conda 용량은 최댓값입니다. 실제 prune으로 확보되는 공간은 대개 이보다 적습니다.
- 백신이 격리함의 파일을 지울 수 있습니다. 이런 항목은 `undo`에서 `STORED_MISSING`으로 표시됩니다.
- 관리자 항목과 관리자 전용 도우미는 v0.2에서 처음 들어갔고, 권한 상승을 흉내 낸 테스트로만 검증했습니다. 아직 여러 실제 PC에서 써 보지 않았습니다.
- 첫 Atlas 스캔은 코드 서명을 확인하느라 30초쯤 걸립니다. 이후 스캔은 결과를 재사용합니다.
- 백신이 아니며, 악성코드를 찾아낸다고 주장하지 않습니다.

## 지원 환경

| 호스트 | 방식 | 상태 |
|---|---|---|
| Claude Code | 플러그인: 스킬, MCP 서버, 승인 훅 | 테스트 완료 |
| Codex CLI | [`AGENTS.md`](AGENTS.md) + `--json` CLI | 테스트 완료 (읽기 전용 스캔, Codex CLI 0.154, 2026-09-26) |
| Gemini CLI | [`AGENTS.md`](AGENTS.md) + `--json` CLI | 최선 지원 |
| Cursor 등 MCP 호스트 | MCP 서버: `npx -y hydra-bane mcp` | 최선 지원 |
| 일반 터미널 | `npx hydra-bane …`, y/N 확인 | 테스트 완료 |

모든 명령은 `--json`을 받으며 `{schema_version, command, ok, data, warnings, error?, hints?}` 형태로 응답합니다. 항목 ID는 실행할 때마다 같습니다(`TEMP`, `NPM`, `NM-3f2a1c`…). 종료 코드: `0` 성공, `1` 오류, `2` 가드가 거부, `3` 사람 확인 필요, `4` 일부만 성공. 에이전트는 대화에서 사용자가 분명히 승인하지 않는 한 `--yes`를 붙이면 안 됩니다. 전체 규칙은 [`AGENTS.md`](AGENTS.md)에 있습니다.

## 명령어

| 명령 | 하는 일 | 무언가 바뀌나요? |
|---|---|---|
| `scan [--only <categories>] [--root <dir>]` | 확보할 수 있는 공간 찾기 | 아니요 |
| `plan --select <ids>` / `--all-safe` | 계획 봉인 | 아니요 (계획 파일만 씀) |
| `apply <plan-id> [--yes]` | 확인 후 적용 | 예 |
| `undo <tx> [--yes]` | 거래 되돌리기 | 예 |
| `explain <id>` | 이 항목을 지워도 되는 이유 | 아니요 |
| `analyze [dir]` | 무엇이 공간을 차지하는지 탐색 (화살표 키) | 아니요 |
| `ledger` | 영수증 검증과 목록 | 아니요 |
| `programs` | 설치된 프로그램 목록 | 아니요 |
| `uninstall <program-id>` | 위 검사를 통과한 프로그램 자체 언인스톨러를 실행하는 계획 봉인 | 아니요 (계획 파일만 씀) |
| `report <program-id>` | 원치 않는 프로그램의 Atlas 제보 미리보기. `--submit`은 승인 후 게시 | `--submit`일 때만 |
| `atlas update` / `atlas status` | 서명된 Atlas 목록을 받아 검증하거나, 설치된 목록을 표시 | 목록 다운로드 |
| `apply-admin <plan-id>` | 계획의 관리자 항목 실행 (UAC 확인) | 예 |
| `admin-install` | npm 원본과 대조한 관리자 전용 도우미 설치 (UAC 확인) | 예 |
| `recover` | 중단된 적용·되돌리기의 영수증 마무리 | 영수증만 |
| `mcp` | 읽기 전용 MCP 서버 실행 (stdio) | 아니요 |

## 로드맵

- **v0.3**: 위협 증거 점검(자동 실행 위치, 서명, YARA·해시 대조. Defender는 2차 의견으로만 쓰고 설정은 건드리지 않음), Atlas 국가 확대(중국, 러시아, 브라질, 일본), 게임을 지운 뒤 남은 드라이버.
- 이후: JSON API 1.0 고정, 외부 보안 감사 결과 공개.

## 응원하기

Hydra-bane 덕분에 디스크 공간이나 골치 아픈 오후를 아꼈다면, 별 하나가 다른 윈도우 사용자들이 이 도구를 찾는 데 도움이 됩니다. 가장 반가운 기여는 내 나라의 Atlas 항목입니다. PC에 딸려 들어와서 지워지지 않던 그 프로그램 말이에요.

## 라이선스

코드: [Apache-2.0](https://github.com/hydra-bane/hydra-bane/blob/main/LICENSE). Atlas 데이터: CC BY-SA 4.0. 이름 사용: [TRADEMARK.md](https://github.com/hydra-bane/hydra-bane/blob/main/TRADEMARK.md). 보안 문제 제보: [SECURITY.md](https://github.com/hydra-bane/hydra-bane/blob/main/SECURITY.md).
macOS용 [Mole](https://github.com/tw93/Mole)에서 영감을 받았으며, Mole과 제휴 관계는 없습니다.
