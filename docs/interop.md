# 互通與驗證結果

「自動」表示有測試程式，每次 `go test` 都會重跑；「手動」表示需要人用外部工具操作，結果填在本檔。

## 1. 自動化測試涵蓋的項目（2026-11-23，Windows amd64，Go 1.27.4）

| 矩陣 | 項目 | 測試 | 結果 |
|---|---|---|---|
| A 傳輸 | 不送 Hello 的連線不卡住其他用戶端；RST、亂碼不讓 accept 迴圈停止；RHE 被拒 | `server/accept_test.go`、`uacp/server_handshake_test.go` | 通過 |
| A 傳輸 | 8192 bytes 緩衝的用戶端收到正確分段的大回應；超過用戶端 MaxMessageSize 回 `BadResponseTooLarge` | `server/hello_test.go` | 通過 |
| B 安全通道 | 五種原則 × Sign / SignAndEncrypt × 金鑰 2048 / 4096（伺服器與用戶端交叉） | `server/x509_test.go` `TestPoliciesWithKeySizes` | 通過 |
| C 換金鑰 | lifetime 2 秒、連續讀取 7 秒、跨四次換金鑰（None 與 SignAndEncrypt） | `server/renew_test.go` | 通過 |
| D 安全反例 | 未提供的原則 / 模式、None 只能做 discovery、未信任 / 過期 / 未生效 / KeyUsage / URI 不符 / 撤銷 / 缺 CRL 的憑證、CreateSession 憑證與 nonce 檢查 | `server/security_policy_test.go`、`server/trust_test.go`、`certs/store_test.go` | 通過 |
| E Session | 匿名、帳密（None 與加密端點）、X509 使用者憑證、錯密碼、未提供的登入方式、session 上限、逾時回收 | `server/p1_test.go`、`server/x509_test.go` | 通過 |
| F 穩定性 | fuzz：`uacp` Hello / Ack、`uasc` chunk 解碼、`verifyAndDecrypt`（含有效簽章的封包）、`ua` 服務解碼，各 15 分鐘，共約 1.7 億次，無 panic | `scripts/fuzz.sh` | 通過（計畫要求每項 ≥ 1 小時，待 Linux 補跑） |
| 功能 | Read / Write / Browse / BrowseNext / Translate、訂閱（含 deadband、刪除節點）、Call、事件與篩選、A&C（觸發、確認、復歸、ConditionRefresh）、HistoryRead（Raw 分頁、AtTime、Events、Processed 聚合） | `server/p1_test.go` ~ `p4_test.go`、`aggregate_test.go` | 通過 |
| 用戶端 | 安全選擇不降級、ReadMany 個別結果、WriteAuto 型別、逾時、伺服器重啟後重連、無 goroutine 洩漏 | `client/client_test.go` | 通過 |
| gopcua 原有測試 | 單元、`tests/go`（integration）、`tests/*`（conformance） | `go test`、`-tags=integration`、`-tags=conformance` | 通過；`TestReadWhileWritingIsRaceFree` 已移除（只針對上游 MapNamespace） |

**`-race`**：Windows 上沒有 C 編譯器，改在 GitHub Actions（ubuntu-latest）執行：單元測試 `-race` 與 integration / conformance 全部通過（2026-11-23，run 45192598881）。人工審查另外找到並修正 4 個 race（見 CHANGES.md）。

## 2. 負載測試（本機，Windows amd64）

`cmd/demoserver -points 3000 -interval 500ms` 搭配 `cmd/uatool stress -clients 10 -points 3000 -interval 500ms`（3000 點 × 10 個訂閱，每 500ms 全部更新一次；這兩個工具現在是 uatester 的 `uatest server` / `uatest stress`）：

Windows amd64（AMD Ryzen 7 PRO 8840U），伺服器與 10 個用戶端在同一台機器，`-history 0`，6 分鐘：

| 時間 | 通知 / 秒 | 用戶端失敗 | 伺服器 goroutine | 伺服器 heap | 伺服器 Sys |
|---|---|---|---|---|---|
| 0:30 | ≈ 55,000 | 0 | 25 | 28 MB | 129 MB |
| 3:00 | ≈ 55,300 | 0 | 25 | 30 MB | 129 MB |
| 6:00 | ≈ 55,300 | 0 | 25 | 32 MB | 129 MB |
| 用戶端全部斷線後 | — | — | 5 | 17–28 MB | 129 MB |

- 理論值為 3000 點 × 10 訂閱 × 每秒 2 次 = 60,000 筆 / 秒。實測約 55,000 筆，差距是因為模擬值四捨五入到 0.1 後，部分更新沒有變化，不會送出通知。
- 6 分鐘內記憶體與 goroutine 數不成長；斷線後 session、訂閱全部回收。
- 第一次測試（`-history 10000`）伺服器 heap 從 68 MB 增加到 429 MB，原因是示範程式自己在記憶體裡保存歷史（3000 點 × 每秒 2 筆），不是程式庫的問題。`-history` 預設改為 200；長測請用 `-history 0` 或小數值。
- **這只是 6 分鐘的煙霧測試，不能取代 72 小時長測**，也不能取代 armv7 上的容量測試。

armv7 長測指令（在工控機上，工具在 uatester 專案）：

```
# 在 uatester 專案編譯：GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -o uatest ./cmd/uatest
./uatest server -addr 0.0.0.0:4840 -host <IP> -points 3000 -interval 500ms -history 0 -stats 10m > soak.log 2>&1
# 另一台機器
uatest stress -ep opc.tcp://<IP>:4840 -clients 10 -points 3000 -interval 500ms -duration 72h
```

判讀：`soak.log` 的 `goroutines`、`heapMB`、`sysMB` 在 72 小時內不應持續上升。

## 3. 手動測試清單（需要人操作）

啟動示範伺服器：

```
uatest server -addr 0.0.0.0:4840 -host <本機 IP> -points 100
# 或開 uatester 桌面版，按「啟動伺服器」
```

帳號：admin/admin（可寫入、可確認警報）、viewer/viewer（唯讀）；匿名唯讀。第一次用加密連線時，伺服器會把 UaExpert 的憑證放進 `pki/rejected/certs`，把它移到 `pki/trusted/certs` 後重新連線即可。UaExpert 也會要求信任伺服器憑證，按 Trust。

| # | 項目（UaExpert） | 預期 | 結果 |
|---|---|---|---|
| 1 | Add Server → 列出端點：None、Basic256Sha256、Aes128_Sha256_RsaOaep、Aes256_Sha256_RsaPss 各 Sign / SignAndEncrypt | 都看得到 | |
| 2 | 用 None + Anonymous 連線，瀏覽 Objects → Plant → P0000_Temp | 看得到值每 0.5 秒變化 | |
| 3 | 每種加密原則 × 模式各連一次（伺服器信任 UaExpert 憑證後） | 都能連、能讀 | |
| 4 | 以 admin 寫入 Setpoint（Int16）、Running（Boolean）、P0000_Temp | 成功，伺服器 log 有 write 紀錄 | |
| 5 | 以 viewer 寫入 Setpoint | 失敗：BadUserAccessDenied | |
| 6 | Data Access View 拖入 20 個點 | 持續更新，無錯誤 | |
| 7 | 對 Plant 呼叫 Reset（輸入任意字串），admin | 成功，Event View 收到事件 | |
| 8 | Event View 訂閱 Server | 收到 P00x0_Temp 的警報事件 | |
| 9 | Alarms & Conditions View | 看到觸發、復歸；以 admin 確認（Acknowledge）成功，log 有 acknowledge | |
| 10 | 關閉並重開 A&C View（觸發 ConditionRefresh） | 未結束的警報補回 | |
| 11 | History Trend View 拖入 P0000_Temp，看最近 10 分鐘 | 有曲線 | |
| 12 | Event History（Server 或 Plant） | 有歷史警報事件 | |
| 12a | `uatest history -node "ns=2;s=P0000_Temp" -agg average -from 10m -interval 1m`（也可試 minimum / maximum / count） | 每分鐘一筆，Count 約 120 | |
| 13 | 連線中拔網路線 30 秒再接回 | UaExpert 自動重連，訂閱恢復 | |
| 14 | 其他上位系統（現場實際使用的 SCADA / BMS） | 能連線、讀值、寫值、收警報 | |

## 4. 尚待執行

- armv7 實機 72 小時長測（3000 點 × 10 訂閱 × 500ms），記錄記憶體與 goroutine 是否成長：`uatest server -stats 10m` 的 log 即可看出。
- Windows 72 小時長測。
- 第 3 節手動清單。
- fuzz 每項 1 小時（Linux）。
- Python asyncua、node-opcua、open62541、.NET 用戶端的互通 CI（§10.1 T16）。
