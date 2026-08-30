# permission-receipt

[English](README.md) | 繁體中文

**每一次「永遠允許」，都應留下收據。**

比對兩個時間點，看看 Claude Code 與 Codex 儲存在磁碟上的持久權限規則，哪些出現了、哪些消失了。完全在本機執行、結果可重現，而且執行時零相依套件。

[![CI](https://github.com/leavemagic-cyber/permission-receipt/actions/workflows/ci.yml/badge.svg)](https://github.com/leavemagic-cyber/permission-receipt/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](pyproject.toml)
[![No telemetry](https://img.shields.io/badge/telemetry-none-success.svg)](#從設計上保護隱私)

```text
PERMISSION RECEIPT
baseline 2026-08-30T09:00:00Z  checked 2026-08-30T09:14:00Z
configured rules only; not effective runtime authorization

ALLOW RULES ADDED (2)
+ claude / local / allow
  Bash(<details withheld>)
  source: <project>/.claude/settings.local.json
  locator: /permissions/allow/2
+ codex / user / allow
  prefix_rule(pattern=<3 positions>, decision="allow")
  source: ~/.codex/rules/default.rules
  locator: lines 8-11
```

規則細節刻意不顯示。這張收據的用途，是幫你找到信任設定的變動；不是把可能含有 token、主機名稱或私人路徑的命令再複製一份。

## 快速開始

直接從 GitHub 安裝：

```bash
pipx install git+https://github.com/leavemagic-cyber/permission-receipt.git
```

或使用 `uv`：

```bash
uv tool install git+https://github.com/leavemagic-cyber/permission-receipt.git
```

開始使用 AI 程式代理前，先保存磁碟上的規則狀態：

```bash
permission-receipt baseline
```

工作結束後再比較：

```bash
permission-receipt check
```

`check` 在沒有變動時以 `0` 結束，發現持久規則變動時回傳 `1`，來源或收據無法安全讀取時回傳 `2`。它絕不修改 Claude Code 或 Codex 的設定。

想先看看效果，又不想讀取任何本機設定，可以執行合成示範：

```bash
permission-receipt demo
permission-receipt demo --format markdown
permission-receipt demo --format json
```

## 它會觀察什麼

工具只擷取下列已記錄的權限值。Claude 的 JSON 設定檔會整份解析，但其他無關欄位在建立快照前就會被丟棄：

| 工具 | 範圍 | 來源 | 讀取資料 |
|---|---|---|---|
| Claude Code | 使用者 | `$CLAUDE_CONFIG_DIR/settings.json` 或 `~/.claude/settings.json` | `permissions.allow`、`ask`、`deny` |
| Claude Code | 專案 | `<project>/.claude/settings.json` | `permissions.allow`、`ask`、`deny` |
| Claude Code | 本機專案 | `<project>/.claude/settings.local.json` | `permissions.allow`、`ask`、`deny` |
| Codex | 使用者 | `$CODEX_HOME/rules/*.rules` 或 `~/.codex/rules/*.rules` | 字面形式的 `prefix_rule(...)` 呼叫 |
| Codex | 專案 | `<project>/.codex/rules/*.rules` | 字面形式的 `prefix_rule(...)` 呼叫 |

目標專案預設為目前的 Git 根目錄，也可以用 `--root` 指定路徑。0.1 版不會重建各家工具特有的 worktree 重新導向，也不處理遠端或雲端設定。

Claude Code 會合併不同範圍的權限陣列，並套用其他信任與政策層。Codex 的專案規則也取決於專案設定層是否受信任，而 execpolicy 語言仍可能變動。因此，這張收據回報的是**磁碟上已設定規則的變動**，不是實際執行時的授權判定。

## 從設計上保護隱私

- 不連網、不呼叫模型、不做遙測，執行時零相依套件。
- 不讀取對話逐字稿、工作階段歷史、驗證資料、`.env` 或 `~/.claude.json`。
- 每個選定的 Claude 設定檔會整份解析，但無關欄位隨即丟棄，不會複製進 baseline 或報告。
- 不保存完整權限規則。Baseline 只包含隨機 salt、加 salt 的指紋、粗略規則形狀、符號化來源名稱與定位資訊。
- Baseline 沒有加密，也沒有簽章。檔案內的 salt 仍可能被拿來離線猜測常見規則；檔案遭修改時，也可能偽造比較結果。請把它當成私密檔案，且不要提交到版本控制。
- 遇到未知或損壞的 JSON、不支援的 `prefix_rule` 語法、無法讀取的檔案、重新導向的來源路徑、收據檔案符號連結、過大的輸入或讀取途中變動時，工具會直接停止，不會假裝成功。
- JSON 與終端輸出都會跳脫控制字元，且不包含實際命令模式。
- Baseline 會以原子方式寫入；在支援 POSIX 權限的系統上，檔案模式會設為 `0600`。

你可以自行檢查 `.permission-receipt/baseline.json`。這個目錄已被本專案忽略，也應該在你的專案中保持未提交狀態。

## 誠實邊界

Permission Receipt 能說的是：

> 兩次快照之間，磁碟上的某條 allow 規則被新增了。

它不能判斷：

- 是哪個介面按鈕、哪個人、哪個 hook 或哪次手動編輯造成變動；
- 是否發生只在當次工作階段有效的允許；
- 某條已設定規則是否真的生效、命中或被更高層規則蓋過；
- 某個操作是否安全；
- 本機看不到的遠端環境發生了什麼。

這些限制是產品的證據邊界，不是含糊的免責聲明。

## 指令

```text
permission-receipt baseline [--root PATH] [--receipt FILE] [--force] [--json]
permission-receipt check    [--root PATH] [--receipt FILE] [--format text|markdown|json]
permission-receipt demo     [--format text|markdown|json]
```

預設 baseline 路徑為 `<project>/.permission-receipt/baseline.json`。除非明確加上 `--force`，否則 `baseline` 不會覆寫既有檔案。

## 為什麼需要它

上游問題追蹤器裡已有人回報這個缺口：

- 在 [Claude Code #40634](https://github.com/anthropics/claude-code/issues/40634) 中，使用者回報現有紀錄無法看出最後是手動允許，還是由規則允許。該 issue 後來因長期沒有活動而自動關閉，並不是因為官方記錄了一個產品修正。
- 在仍開放的 [Codex #27157](https://github.com/openai/codex/issues/27157) 中，使用者回報持久命令允許規則沒有應用程式內的檢視或移除介面，只能手動編輯檔案。

Permission Receipt 不會假裝能重建過去每一次允許事件。它處理的是更小、但可以驗證的問題：**磁碟上的持久規則資料究竟改了什麼？**

目前的競品掃描與產品定位記錄在 [docs/landscape.md](docs/landscape.md)。

## 開發

```bash
python -m pip install -e .
python -B -m unittest discover -s tests -v
permission-receipt demo --format json
```

測試 fixture 與產品聲明規則請見 [CONTRIBUTING.md](CONTRIBUTING.md)。安全性問題請使用 [GitHub 私密漏洞回報](https://github.com/leavemagic-cyber/permission-receipt/security/advisories/new)，不要建立公開 issue。

## 授權

MIT
