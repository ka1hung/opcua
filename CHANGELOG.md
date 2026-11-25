**繁體中文** | [English](CHANGELOG.en.md)

# 版本紀錄

與 gopcua 基準的逐項差異見 [docs/CHANGES.md](docs/CHANGES.md)。

## v0.2.3（2026-11-25）

- 用戶端 `Subscribe` 不限點數：依伺服器的 MaxMonitoredItemsPerCall 分批建立監控項目；訂閱滿了（Bad_TooManyMonitoredItems）自動再開一個訂閱。之前一次全部送出，超過伺服器上限（本套件伺服器預設單一請求 5,000 個）就整個失敗。`Subscription.Count()` 回報用了幾個訂閱。
- 用戶端支援 `nsu=<命名空間 URI>;<id>` 形式的 NodeID（讀、寫、訂閱、瀏覽、方法、歷史全部適用），伺服器重新啟動後命名空間順序改變也不受影響；`Client.NSU` 把 `ns=` 轉成 `nsu=`。
- 用戶端 `Options.VerifyServer`：連線前檢查伺服器憑證，可用來記住第一次看到的憑證（TOFU）；`Options.ApplicationName` 設定伺服器看到的應用程式名稱；`EndpointInfo.Thumbprint` 與 `CertThumbprint`。
- 伺服器：`Server.SessionOf(ctx)` 在寫入、方法、確認警報的回呼裡取得是哪個用戶端；`SessionInfo` 增加 ClientName、ClientAddr、Created、MonitoredItems；`Server.CloseSession` 中斷連線。
- 信任清單：`certs.Store` 增加 `Trusted`、`Untrust`、`DeleteRejected`。

## v0.2.2（2026-11-25）

安全性修正（感謝私下通報）：

- **解碼器遞迴深度**（未驗證即可觸發的 DoS）：Variant、DataValue、DiagnosticInfo、ExtensionObject 可以無限巢狀，一個不到 2 MiB 的訊息就能讓伺服器 stack overflow 直接結束程序（recover 攔不住）。巢狀深度上限改為 100，超過回 `BadEncodingLimitsExceeded`。
- **IndexRange 溢位**：IndexRange 上界設成 int 最大值時，下次值變動會在沒有 recover 的 goroutine panic，整個伺服器結束；32 位元（armv7）上觸發值只是 `2147483647`。
- **用戶端憑證綁定**：用戶端原本接受 OpenSecureChannel 回應裡換掉的伺服器憑證，TrustStore 只保護第一次連線，自動重連時中間人可以冒充伺服器並取得使用者密碼。現在回應的憑證與安全原則必須和開通道時相同；CreateSession 的伺服器憑證也必須是通道的憑證，簽章驗證失敗改回傳錯誤（之前只寫 log）。
- **訂閱的讀取權限**：推送型（`AddVariable` 加的變數）監控項目只在建立時檢查 `CanRead`，之後取消權限，訂閱仍持續收到新值。現在每個值都會檢查，被拒時送 `BadUserAccessDenied`，恢復權限後繼續送值。
- **憑證撤銷**：個別信任（放在 `trusted/certs`）的 CA 簽發憑證不會檢查 CRL，`RequireCRL` 也沒作用，被 CA 撤銷後仍可連線。現在會到簽發者的 CRL 檢查撤銷；找不到簽發者時，`RequireCRL` 會拒絕。

## v0.2.1（2026-11-24）

- **32 位元（armv7）修正**：安全通道與 monitor 的 64 位元計數器在 32 位元平台沒有對齊，收到第一個服務請求就 panic、連線被關閉（用戶端看到 BadTCPInternalError）。CI 加上 32 位元測試。
- 伺服器：用戶端用不在設定清單裡的位址連線時（例如用 IP 連、伺服器設定的是主機名稱），回報的端點網址改用用戶端所用的位址，沒有 DNS 的內網也連得上。
- 用戶端修正：伺服器回報的端點網址若用用戶端查不到的主機名稱（現場很常見），改連使用者指定的主機（保留回報的埠與路徑）；之前會卡在 DNS 查詢而連不上。

## v0.2.0（2026-11-24）

- 伺服器：`Server.AddReference`，在兩個已存在的節點之間加參照（例如讓舊資料夾也列出同一個點位，不必複製節點）。

## v0.1.0（2026-11-24）

第一個公開版本，以 gopcua v0.9.2 為基礎。

- 安全通道加固：加密原則不可降級、用戶端憑證驗證與 PKI 目錄、chunk 上限、遠端 panic 防護。
- 伺服器重寫：位址空間、讀寫、瀏覽、訂閱、身分驗證與權限、方法、事件、警報（A&C）、歷史（Raw、AtTime、Processed、Events）。區域物件會收到底下點位的事件與警報；ConditionRefresh 不會改變警報的 EventId，多個用戶端可以同時確認警報。
- 新的高階用戶端套件 `client`，功能與伺服器對應：讀寫、瀏覽、節點屬性、訂閱（deadband、佇列、觸發條件）、方法呼叫、事件與警報（訂閱、Refresh、確認）、歷史、伺服器狀態、端點列表。
- 測試工具在獨立專案 [uatester](https://github.com/ka1hung/uatester)。
