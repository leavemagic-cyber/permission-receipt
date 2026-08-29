# permission-receipt

**每一次「永遠允許」，都應留下收據。**

`permission-receipt` 比對兩個時間點的 Claude Code／Codex 持久權限規則，告訴你哪些 allow、ask、deny 規則出現或消失。它完全在本機運作、結果可重現、執行時零相依套件。

## 快速開始

```bash
pipx install git+https://github.com/leavemagic-cyber/permission-receipt.git
permission-receipt baseline
# 使用 Claude Code 或 Codex
permission-receipt check
```

也可以先跑不讀取任何本機設定的合成示範：

```bash
permission-receipt demo
permission-receipt demo --format json
```

`check` 在沒有變更時回傳 `0`，發現持久規則 drift 時回傳 `1`，來源或收據無法安全讀取時回傳 `2`。它絕不修改兩套 agent 的設定。

## 它實際讀什麼

- Claude Code：user、project、local 三個 scope 的 `settings.json`，且只取 `permissions.allow`、`ask`、`deny`。
- Codex：user 與 project 的 `rules/*.rules`，且只接受可安全解析的 literal `prefix_rule(...)`。

它不讀 transcript、session history、auth、`.env` 或 `~/.claude.json`。選定的 Claude settings JSON 會整份解析，但其他欄位隨即丟棄，不會複製進 baseline／report；完整 command/specifier 也不會存入 baseline。baseline 只保存隨機 salt、salted fingerprint、規則粗略形狀、symbolic source 與定位。baseline 不是加密或簽章檔；保存的 salt 仍可能被用來離線猜測常見規則，檔案遭修改也能偽造比較結果，所以必須保持私密且不要 commit。

## 誠實邊界

它能證明的是：

> 兩次 snapshot 之間，某條磁碟上的持久規則被新增或移除。

它不能判斷：

- 是誰、哪個按鈕、hook 或手動編輯造成；
- session-only approval；
- 規則在 runtime 是否有效、命中或被更高層 policy 蓋過；
- 操作本身是否安全；
- 本機看不到的 remote/cloud 設定。

這些不是模糊的免責聲明，而是 v0.1 明確不跨越的證據界線。

完整安裝、scope、輸出格式與開發說明請見 [英文 README](README.md)。

MIT License
