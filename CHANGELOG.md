**繁體中文** | [English](CHANGELOG.en.md)

# 版本紀錄

與 gopcua 基準的逐項差異見 [docs/CHANGES.md](docs/CHANGES.md)。

## v0.2.0（2026-11-24）

- 伺服器：`Server.AddReference`，在兩個已存在的節點之間加參照（例如讓舊資料夾也列出同一個點位，不必複製節點）。

## v0.1.0（2026-11-24）

第一個公開版本，以 gopcua v0.9.2 為基礎。

- 安全通道加固：加密原則不可降級、用戶端憑證驗證與 PKI 目錄、chunk 上限、遠端 panic 防護。
- 伺服器重寫：位址空間、讀寫、瀏覽、訂閱、身分驗證與權限、方法、事件、警報（A&C）、歷史（Raw、AtTime、Processed、Events）。區域物件會收到底下點位的事件與警報；ConditionRefresh 不會改變警報的 EventId，多個用戶端可以同時確認警報。
- 新的高階用戶端套件 `client`，功能與伺服器對應：讀寫、瀏覽、節點屬性、訂閱（deadband、佇列、觸發條件）、方法呼叫、事件與警報（訂閱、Refresh、確認）、歷史、伺服器狀態、端點列表。
- 測試工具在獨立專案 [uatester](https://github.com/ka1hung/uatester)。
