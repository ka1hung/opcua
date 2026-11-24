**繁體中文** | [English](README.en.md)

# 測試

這裡放的是比較大型的測試：需要另外架伺服器、模擬異常的網路對手，或連到第三方實作。一般的單元測試放在各套件裡（例如 `server/p1_test.go`），`go test ./...` 就會跑；這裡的測試要加 build tag 才會跑，CI 每次都會跑。

## 執行

```
go test -tags=integration ./tests/go/...       # 低階用戶端 ↔ 本專案伺服器
go test -tags=integration ./tests/python/...   # 低階用戶端 ↔ Python opcua 伺服器（需要 pip3 install opcua）
go test -tags=conformance ./tests/...          # 其餘全部（規範行為測試）
```

- 加 `-race` 需要 C 編譯器（cgo）。Windows 沒有安裝的話，以 GitHub Actions 的結果為準。
- `tests/go` 固定使用 4840 埠，不要和其他佔用 4840 的程式同時跑。

## 各資料夾

| 資料夾 | 測什麼 | 對手 | 測試數 |
|---|---|---|---|
| `go/` | 讀寫、命名空間、加密連線、PKCS#8 私鑰、統計 | 本專案的伺服器 | 8 |
| `python/` | 讀寫、方法、斷線重連、逾時、未知節點；目前唯一和第三方實作的互通測試 | Python opcua 伺服器 | 9 |
| `reconnect/` | 斷線後通知有沒有遺漏、訂閱能不能恢復、Republish、何時重建 session | 腳本式假伺服器（可以指定時間點斷線） | 15 |
| `securechannel/` | 安全權杖的有效期計算、ServiceFault 不會關閉通道、拒絕過期權杖、驗證序號 | 腳本式假伺服器 | 4 |
| `securitypolicy/` | 開通道時 RSA-OAEP 每個區塊都填滿、None 原則下的用戶端 nonce | 腳本式假伺服器 | 2 |
| `session/` | 帳密登入時用哪個加密原則（空白時沿用通道的原則；多個原則時選端點自己的） | 本專案的伺服器（換掉 ActivateSession 處理函式，只記錄請求） | 2 |
| `transport/` | TCP 握手遇到期限或取消時會放棄；主機名稱有多個 IP 時會試下一個 | 只收不回的假伺服器 | 3 |
| `encoding/` | 編碼邊界：DateTime 範圍、空值、Variant 陣列長度與維度造假 | 不連線，直接呼叫 `ua.Encode` / `ua.Decode` | 9 |
| `server/` | 換金鑰期間用戶端持續可用；訂閱中的點位 `SetValue` 不會卡住 | 本專案的伺服器 | 2 |
| `internal/scriptedpeer/` | 不是測試；`transport`、`securitypolicy`、`securechannel` 共用的腳本式假伺服器核心 | — | — |

## 寫法慣例

**一個檔案只測一個行為。** 檔名就是那個行為的英文句子，例如 `expired_security_token_is_rejected_test.go`，裡面只有一個 `func Test`。

**檔頭註解依序寫：**
1. 測的行為，引用規範條文（例如 OPC 10000-4 §5.13）。
2. 和相鄰的測試有什麼不同。
3. 用的是哪個測試環境，最後一句固定寫 `See harness.go.`（檢查方式：`grep -c "See harness.go" tests/<資料夾>/*_test.go`，每個測試檔都應該是 1）。
4. 斷言什麼，以及刻意不斷言什麼。
5. 參考過哪些其他實作（open62541、UA-.NETStandard、Eclipse Milo、node-opcua）。

**程式放哪裡：**
- 同一資料夾兩個以上測試共用的程式放 `harness.go`。
- 只有一個測試用的 helper 跟那個測試放在一起。
- 兩個以上資料夾共用的放 `internal/`。
- helper 只回傳值；只有 `Test` 函式本身呼叫 `t.Errorf` / `t.Fatalf`。

**三種結果，後兩種都會讓 CI 變紅：**

| 結果 | 意思 | 寫法 |
|---|---|---|
| 通過 | 程式庫行為正確 | — |
| 失敗 | 程式庫行為錯誤，或程式庫自己的錯讓測試無法判定 | `t.Errorf` |
| 無法判定 | 測試環境的問題：埠被佔用、假伺服器出錯、機器太慢超過時限 | `t.Fatalf("could not set the test up: ...")` |

**判定依據要來自被測程式之外。** 自己編碼、自己解碼，只能證明程式和自己一致，證明不了送出去的位元組是對的；兩邊程式同時錯，測試照樣會過。所以判定要靠外部的證據：
- 測試裡寫死的位元組（從規範或其他實作讀來，並在檔頭註明出處）；
- Go 標準函式庫，例如用 `crypto/rsa` 解密驗證；
- race detector、時鐘（用逾時判定卡死）；
- 腳本式假伺服器記錄下來的實際收送內容。

## 尚未修好的行為（knownBug）

規範要求、但程式庫還沒做到的行為，測試裡會宣告一個 `knownBug` 常數：
- 測試照跑，失敗時印出 `known bug:`，不會讓 CI 變紅。
- 修好之後測試會通過，並且**故意報錯**，提醒你把 `knownBug` 常數和只有它用到的程式一起刪掉，在同一個 commit 裡完成。
- 不知道為什麼突然通過時，不要刪常數，先查清楚。

目前只有一個：`reconnect/no_acknowledgements_when_nothing_is_available_test.go`。伺服器不保留重送佇列（availableSequenceNumbers 是空的）時，用戶端仍然會回確認。

## 審查新測試時要問的問題

只會通過、其實什麼都沒檢查的測試，比沒有測試更糟，因為大家會相信它。

1. 失敗的分支真的有可能執行到嗎？實際追一遍程式。
2. 結果取決於被測程式，還是取決於測試環境自己的狀態？
3. 刪掉「看起來執行不到」的分支前，先確認正確的實作會不會走到。
4. 在還沒修的程式上能編譯嗎？只因為缺少某個新函式而失敗的測試，測的是名字，不是行為。
5. 要測的狀況是確實製造出來的，還是碰運氣等它發生？
6. 換成一個已知正確的實作（讀它的原始碼），會不會也失敗？會的話，多半是測試寫錯了。

## 還沒有測試的部分

**reconnect**（OPC 10000-4 §6.7 的用戶端行為），受限於假伺服器目前做不到的事：
- ActivateSession 失敗的情境：只在啟用失敗時才建新 session、TransferSubscriptions 失敗時重建訂閱。假伺服器目前一律核准啟用。
- 在加密端點上重連：沿用同一個加密原則、應用程式憑證與帳號。
- 通道層憑證錯誤時改呼叫 GetEndpoints。
- 用 ResendData 方法補回資料。
- 連線沒有中斷、只是沒有回應時，靠訂閱的 keep-alive 偵測。
- Reverse connect。
- 用戶端內部 pause / resume 兩個訊號的競態（gopcua issue #895）：這是 goroutine 排程問題，黑箱測試抓不到，需要另一種測法。

以下兩項是應用程式的責任，不是程式庫的，所以不列為測試：訂閱 ServerStatus 偵測伺服器關機、避免 Republish 的舊值蓋掉較新的值。

**session**：模式為 None 的端點不能使用 ECC / RSA_DH 加密原則。程式庫目前根本沒有實作 ECC / RSA_DH，等實作時再補。
