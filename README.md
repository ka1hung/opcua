**繁體中文** | [English](README.en.md)

# opcua

給工控設備用的 OPC UA 伺服器與用戶端，純 Go 撰寫。

適合放在控制器或閘道器上：把現場點位以 `ns=2;s=<點位名稱>` 開放給 SCADA、BMS、MES 等上位系統讀寫、訂閱，並提供警報與歷史資料；也能當用戶端去連 PLC 與其他 OPC UA 伺服器。

- **純 Go，不需要 cgo**：`CGO_ENABLED=0` 一行交叉編譯到 Windows amd64、Linux amd64、Linux armv7。
- **安全預設**：伺服器只接受設定過的加密組合，不會被降級成 None；用戶端憑證要經過信任清單；匿名登入預設唯讀。
- **完整的伺服器功能**：讀寫、瀏覽、訂閱（含 deadband、Republish）、方法、事件、警報（Alarms & Conditions）、歷史（Raw、AtTime、Processed、Events）。
- **好用的用戶端**：自動選擇最安全的端點、批次讀取、自動轉型寫入、斷線自動重連。

## 安裝

```
go get github.com/ka1hung/opcua
```

需要 Go 1.23 以上。

## 快速開始

### 伺服器

```go
cert, key, _, _, err := certs.LoadOrCreate("pki/own/cert.der", "pki/own/key.pem",
	certs.Spec{ApplicationURI: "urn:host:app", Hosts: []string{"192.168.1.10"}}, true)
store, err := certs.Open("pki", certs.Options{})

srv := server.New(
	server.Certificate(cert), server.PrivateKey(key),
	server.EndPoint("192.168.1.10", 4840), server.ListenAddress("0.0.0.0:4840"),
	server.EnableSecurity("None", ua.MessageSecurityModeNone),
	server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
	server.EnableAuthMode(ua.UserTokenTypeAnonymous), // 匿名只能讀
	server.EnableAuthMode(ua.UserTokenTypeUserName),
	server.UserNameAuthenticator(func(ctx context.Context, user, pass string) (*server.Identity, error) { ... }),
	server.TrustStore(store),
)

ns := srv.AddNamespace("urn:host:app:points") // 第一個自訂命名空間固定是 ns=2
folder, _ := srv.AddFolder(server.ObjectsFolder, ua.NewStringNodeID(ns, "Points"), "Points")
srv.AddVariable(folder.ID(), server.VariableSpec{
	NodeID: ua.NewStringNodeID(ns, "AHU01_Temp"), BrowseName: "AHU01_Temp",
	DataType: ua.TypeIDDouble, Writable: true, Unit: "°C", EURange: &server.Range{Low: 0, High: 50},
	CanWrite: func(who *server.Identity) bool { return who.UserName == "admin" },
})
srv.OnWrite(func(ctx context.Context, who *server.Identity, node *ua.NodeID, v *ua.Variant) ua.StatusCode { ... })
srv.Start(ctx)

// 現場資料更新時
srv.SetValue(ua.NewStringNodeID(ns, "AHU01_Temp"), 21.5, ua.StatusOK, time.Now())
srv.SetAlarm(server.Alarm{Source: id, Name: "High", Active: true, Severity: 700, Message: "AHU01 溫度過高"})
```

### 用戶端

```go
c, err := client.Dial(ctx, "opc.tcp://plc:4840", client.Options{
	Security: client.Auto(client.MinSign), // 找不到夠安全的端點就回錯誤，不會退回 None
	Auth:     client.UserPass("user", "pw"),
})
results := c.ReadMany(ctx, []string{"ns=2;s=A", "ns=2;s=B"})
err = c.WriteAuto(ctx, "ns=2;s=Setpoint", 23)
sub, _, err := c.Subscribe(ctx, ids, 500*time.Millisecond, func(id string, r client.Result) { ... })
```

用戶端功能和伺服器一一對應：

| 伺服器提供 | 用戶端 |
|---|---|
| 端點與加密 | `client.Endpoints`（連線前列出端點）、`Dial` |
| 讀寫 | `ReadMany`、`WriteAuto`、`Attributes`（資料型別、權限、說明等屬性） |
| 瀏覽 | `Browse`、`Translate`（用路徑找節點） |
| 訂閱 | `Subscribe`、`SubscribeWith`（deadband、佇列、取樣、觸發條件） |
| 方法 | `MethodArguments`、`Call`（參數依方法定義自動轉型） |
| 事件與警報 | `SubscribeEvents`、`Refresh`（補回已作用的警報）、`Acknowledge` |
| 歷史 | `HistoryRaw`、`HistoryAtTime`、`HistoryProcessed`、`HistoryEvents` |
| 伺服器資訊 | `ServerStatus`、`Namespaces` |

```go
events, err := c.SubscribeEvents(ctx, client.ServerObject, time.Second, func(e client.Event) {
	if e.IsCondition() && e.Active && !e.Acked {
		_ = c.Acknowledge(ctx, e, "已處理")
	}
})
_ = events.Refresh(ctx) // 連線前就已作用中的警報也送過來

out, err := c.Call(ctx, "ns=2;s=Plant", "ns=2;s=Plant.Reset", "維修")
avg, err := c.HistoryProcessed(ctx, "ns=2;s=AHU01_Temp", client.Average, start, end, 10*time.Minute)
```

## 目錄

| 路徑 | 內容 |
|---|---|
| `server/` | 伺服器 |
| `client/` | 高階用戶端（一般程式用這個） |
| `certs/` | 自簽憑證產生、信任清單（trusted / issuers / rejected 目錄） |
| `ua/`、`uasc/`、`uacp/`、`uapolicy/` | 編碼、安全通道、傳輸、加密原則 |
| 根目錄（`opcua`） | 低階用戶端，`client/` 建立在它上面 |
| `cmd/id/`、`cmd/service/`、`cmd/status/`、`schema/` | 從 OPC UA 規範檔產生 `ua/`、`id/` 程式碼（`go generate`） |
| `tests/` | 整合測試與 conformance 測試 |
| `docs/` | 與 gopcua 的差異紀錄、互通測試結果 |

## 測試工具

模擬伺服器、現場診斷與壓力測試工具在另一個專案 **uatester**（`ka1hung/uatester`），有 Windows 桌面版與可以跑在 armv7 的命令列版 `uatest`。

## 測試

```
go test ./...                                  # 單元測試
go test -tags=integration ./tests/go/...       # 用戶端對本伺服器
go test -tags=conformance ./tests/...          # conformance 測試
scripts/fuzz.sh 1h                             # fuzz，每個目標各跑 1 小時
```

`-race` 需要 C 編譯器（cgo）；Windows 沒有裝的話以 GitHub Actions 的結果為準。

## 文件

- [docs/CHANGES.md](docs/CHANGES.md)：與 gopcua 基準的逐項差異（底層每筆修改都記在這裡，方便日後比對上游的安全修正）
- [docs/interop.md](docs/interop.md)：互通測試結果與 UaExpert 手動檢查清單
- [tests/README.md](tests/README.md)：大型測試的說明與寫法慣例
- [CHANGELOG.md](CHANGELOG.md)：版本紀錄

## 參考專案

這個套件站在兩個開源專案的肩膀上：

- **[gopcua/opcua](https://github.com/gopcua/opcua)**（MIT）：本專案從它的 v0.9.2（commit `b76fd80`）分支出來。編碼、傳輸、安全通道、加密原則與低階用戶端沿用 gopcua，並補強了伺服器端的安全檢查；伺服器則依 OPC UA 規範整個重寫。
- **[awcullen/opcua](https://github.com/awcullen/opcua)**（MIT）：伺服器功能範圍與 API 設計的參考（方法、事件、身分驗證、歷史等）。只參考設計，沒有使用它的程式碼。

本專案獨立維護，不會回饋上游；問題請不要回報到上述兩個專案。

## 授權

MIT，見 [LICENSE](LICENSE) 與 [NOTICE](NOTICE)。沿用自 gopcua 的檔案保留原本的版權聲明。
