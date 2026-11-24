# 與 gopcua 基準的重大差異

基準：`github.com/gopcua/opcua` v0.9.2（commit b76fd80）。本 repo 不含 gopcua 的 git 歷史；要比對上游時，另外 clone gopcua，看 v0.9.2 之後 `ua`、`uasc`、`uacp`、`uapolicy` 的修改，對照本檔決定是否手動移植。
本檔記錄所有與基準不同的地方。`ua`、`uasc`、`uacp`、`uapolicy` 的每筆修改都要記在這裡，以便日後比對上游安全修正。

## v0.1.0（2026-11-24）

### 建庫
- module path 改為 `github.com/ka1hung/opcua`（只改 `.go` 與 `go.mod`；Markdown 中指向上游 issue / PR 的連結保留）。
- 新增 `.gitattributes`，所有文字檔固定 LF。
- 新增 `NOTICE`、`CHANGES.md`、`plan.md`。
- CI 改為自己的 `.github/workflows/go.yml`（Linux `-race` 測試、整合 / conformance 測試、三平台 `CGO_ENABLED=0` 交叉編譯）；移除上游的 `stale.yml`。

### P0 加固
- **T5 accept 迴圈 DoS**（`uacp`、`server`）：
  - `uacp`：新增 `Listener.AcceptConn`（只接 TCP）與 `Conn.ServerHandshake(ctx, endpoint)`（握手受 ctx 期限 / 取消約束）。`Listener.Accept` 保留，改為兩者組合並套用 `DefaultHelloTimeout`（10 秒）。
  - `server`：accept 迴圈只接 TCP，每個連線在自己的 goroutine 握手，不會因單一不送 Hello 的連線卡住其他用戶端；只有 listener 關閉或 ctx 結束才離開迴圈，其他錯誤（例如用戶端 RST）記錄後退避重試（5 ms 起，最長 1 秒）。新增 `server.HelloTimeout(d)` 選項。
- **T12 RHE SSRF**（`uacp`）：伺服器收到 ReverseHello 一律回 `BadTCPMessageTypeInvalid` 並結束握手，不再連到用戶端指定的位址。
- **T4 遠端可觸發 panic**（`uasc`、`uapolicy`、`server`）：
  - `uasc.verifyAndDecrypt`：切片前檢查 chunk 長度、簽章長度、PaddingSize；檢查每個 Padding byte 都等於 PaddingSize（Part 6 §6.7.2.5）；不符一律回 `BadSecurityChecksFailed`。
  - `uapolicy.PublicKey`：憑證不是 RSA 金鑰時回錯誤，不再型別斷言 panic；`uasc/secure_channel_crypto.go` 四處改用它。
  - `server`：讀取安全通道（`receiveSafe`）與每個服務 handler（`callHandler`）各加 `recover()`。讀取端 panic 只結束該通道；handler panic 只讓該請求回 `BadInternalError`。
- **T9 通道錯誤處理**（`server`）：通道因錯誤結束時，先送 ERR 訊息（帶錯誤的狀態碼，沒有狀態碼時用 `BadTCPInternalError`）再關閉 TCP 連線（上游兩者都不做）。CLO 驗簽、abort chunk 處理尚未完成。
- **T10 未完成 chunk 無上限**（`uasc`）：中間 chunk 改由 `chunkBuffer` 保存。每個請求在接收時就檢查 chunk 數（MaxChunkCount）與累計大小（MaxMessageSize），不必等合併後；同時等待中的請求最多 64 個，總量最多 64 × MaxMessageSize。超過就丟棄該請求並回錯誤。MaxChunkCount / MaxMessageSize 為 0 視為不限制（Part 6 §7.1.2.3），上游在 MaxChunkCount 為 0 時會拒絕所有中間 chunk。
- **T1 加密原則降級**（`uasc`、`server`）：
  - `uasc.Config.AllowedSecurity`：伺服器通道對每個 OPN 檢查原則與模式；原則不允許回 `BadSecurityPolicyRejected`，模式不允許或組合無效（None 原則只能配 None 模式，其他原則只能配 Sign / SignAndEncrypt）回 `BadSecurityModeRejected`。
  - `server`：只允許 `EnableSecurity` 設定的組合。None 通道一律可開，但若 None 未啟用，該通道只能呼叫探索服務（FindServers、FindServersOnNetwork、GetEndpoints），其他服務回 `BadSecurityPolicyRejected`（OPC 10000-4 §5.4.1）。
  - `server.Start`：沒有呼叫任何 `EnableSecurity` 時回錯誤（上游會接受任何組合）。
- **用戶端收不到 ERR 原因**（`uasc`）：`readChunk` 先判斷 `len(b)==0` 當成 EOF，把 uacp ERR 吃掉；改為先檢查 `*uacp.Error`。
  - 已知未修（P5）：用戶端收到 ERR 時，等待中的請求仍只拿到 EOF（ERR 的 RequestID 為 0，對不到等待中的請求），原因只送到 errch。
- **T2 用戶端憑證驗證與 PKI**（新套件 `certs`、`uasc`、`server`）：
  - `certs.Store`：OPC 10000-12 §F.1 目錄結構（`trusted/certs`、`trusted/crl`、`issuers/certs`、`issuers/crl`、`rejected/certs`）。驗證信任（憑證本身或其鏈上任一張在 trusted）、憑證鏈（含用戶端送來的中繼憑證）、有效期（可設 `ClockSkew`）、KeyUsage、ApplicationURI、CRL 撤銷（預設沒有 CRL 也接受，`RequireCRL` 可改為拒絕）。不信任的憑證存到 rejected（數量上限，預設 100）；`AutoTrust` 自動信任；`Trust` 把憑證移到 trusted。操作員手動增刪檔案不必重啟（依目錄修改時間重新載入）。
  - `certs.NewSelfSigned`、`certs.LoadOrCreate`、`certs.Matches`：產生自簽應用程式憑證；憑證不含目前的 ApplicationURI / 位址或 30 天內到期時，可選擇重新產生或只回警告（§5「改 IP 後憑證不符」）。
  - `uasc.Config.VerifyPeerCertificate`：伺服器通道在 OPN 時驗證用戶端憑證，不通過回對應的 `BadCertificate*` 狀態碼（經 ERR 告知用戶端）。
  - `server.TrustStore(store)` 選項；未設定時接受所有憑證，`Start` 記警告。
- **T14（部分）CreateSession 檢查**（`server`）：安全通道下，用戶端憑證必須與開通道的憑證相同（否則 `BadSecurityChecksFailed`）、ClientNonce 至少 32 bytes（`BadNonceInvalid`）、有 TrustStore 時驗證憑證並比對 ClientDescription.ApplicationUri（`BadCertificateUriInvalid`）。
- **T9 其餘**（`uasc`、`server`）：CLO 先驗簽（與 MSG 相同）才關閉通道，未驗證的 CLO 不能關掉加密通道。abort chunk（`A`）只放棄該請求，通道保留（上游會拆掉整個通道）；新增 `MessageBody.Aborted()`。
- **T16（部分）fuzz**：`uacp.FuzzDecode`、`uasc.FuzzMessageChunkDecode`、`uasc.FuzzVerifyAndDecrypt`、`ua.FuzzDecodeService`；`scripts/fuzz.sh`（預設每項 1 小時；原為 `make fuzz`）。

### P1：伺服器重寫（`server/`）
`server/` 依 OPC UA 規範重寫（不沿用上游的 NodeNameSpace / MapNamespace / 訂閱實作；awcullen 只作設計參考）。公開 API 改變，見 README。

- **請求處理（S1、T6、T11）**：每個安全通道的請求並行處理（上限 `Limits.RequestsPerChannel`，預設 16），不再由單一 goroutine 依序處理全伺服器的請求。Handler 改為 `func(ctx, *Request)`；session 查找、通道綁定、是否已啟用集中在分派處檢查（`BadSessionIdInvalid`、`BadSecureChannelIdInvalid`、`BadSessionNotActivated`）。ServiceFault 帶回請求的 RequestHandle。每個請求有 `recover()`。`Limits`：連線、session、每 session 訂閱數、每訂閱監控項目數、單次請求節點數、continuation point、Publish 佇列、重送佇列、佇列大小、最小發布 / 取樣間隔、session 逾時範圍、寫入逾時。
- **Session（S1）**：AuthenticationToken 改用 crypto/rand 的 32 bytes；session 綁定通道，換通道重新啟用時須為同一用戶端憑證；session 逾時回收（連同訂閱）；CloseSession 依 DeleteSubscriptions 處理，否則訂閱保留到 lifetime 結束或被 Transfer。
- **身分驗證（S2、T3）**：Anonymous、UserName、X509 三種 token；`UserNameAuthenticator`、`CertificateAuthenticator` 回呼。UserName 依 token policy 用伺服器私鑰解密並**比對目前的 server nonce**（防重放）；None 端點上的 UserName / X509 token 一律以 Basic256Sha256 加密 / 簽章，密碼不會明文傳送。X509 使用者憑證以 `UserTrustStore`（預設同 TrustStore）驗證並驗 UserTokenSignature。沒有啟用任何登入方式時 `Start` 回錯誤。
- **位址空間（S3）**：新的 `AddressSpace`（節點各自加鎖、雙向參照、可刪除）。ns0 從內嵌 NodeSet2 匯入，新寫的匯入器會解析值（Argument、EnumValueType、字串、數字、LocalizedText 等）、DataType、ValueRank（未寫時為 -1）、AccessLevel，並依 NamespaceUris 重新對應 namespace。比較 NodeId 不再經過 `fmt`（上游的 `NodeID.Equal` 會格式化字串，匯入時間 6.7 秒 → 0.7 秒）。Server 物件的動態值：ServerStatus（含子節點）、NamespaceArray、ServerArray、ServiceLevel、ServerCapabilities / OperationLimits。
- **權限（S4）**：每個變數可設 `CanRead`、`CanWrite`；`AnonymousReadOnly`（預設開）；UserAccessLevel、UserExecutable 依使用者計算；無權限回 `BadUserAccessDenied`，AccessLevel 本身不允許回 `BadNotReadable` / `BadNotWritable`。
- **Read / Write**：TimestampsToReturn、IndexRange（一維）、DataEncoding、MaxAge 檢查。Write 只允許 Value；依 DataType / ValueRank 檢查型別，`LenientWriteTypes`（預設開）時數值與 Boolean 之間可轉換並檢查範圍（超出回 `BadOutOfRange`，小數寫入整數回 `BadTypeMismatch`）。寫入回呼（全域 `OnWrite` 或變數自己的）同步回傳狀態碼，受 `Limits.WriteTimeout` 限制（逾時回 `BadTimeout`）；回傳 Good 才儲存。
- **Browse 等（S6）**：Browse（方向、參照型別含子型別、NodeClassMask、ResultMask、TypeDefinition）、BrowseNext（session 範圍的 continuation point，有上限）、TranslateBrowsePathsToNodeIds、Register / UnregisterNodes、FindServers（ServerUris 篩選）、GetEndpoints（網址不符時回全部端點）。
- **訂閱（S5）**：每個訂閱一個狀態機（Part 4 §5.13.1）：參數修正（lifetime ≥ 3×keepalive 等）、keep-alive、lifetime 到期（有 Publish 時送 `BadTimeout` StatusChange）、late 狀態與 Publish 到達時立即補送、MaxNotificationsPerPublish 與 MoreNotifications、重送佇列與 Acknowledge、Republish、ModifySubscription、SetPublishingMode、TransferSubscriptions（同一使用者才可、SendInitialValues）、Publish 佇列上限（`BadTooManyPublishRequests`）與 TimeoutHint。監控項目：值改變時由 `SetValue` 推送；動態值節點（如 CurrentTime）依取樣間隔讀取；佇列大小與 DiscardOldest、溢位位元；DataChangeFilter（Status / StatusValue / StatusValueTimestamp）、Absolute deadband（含陣列）、**Percent deadband（需 EURange，沒有時回 `BadMonitoredItemFilterUnsupported`）**；MonitoringMode；Modify / SetMonitoringMode / Delete。節點被刪除時送 `BadNodeIdUnknown`。
- **API（§5.1）**：`AddNamespace`（第一個為 ns=2）、`AddFolder`、`AddObject`、`AddVariable(VariableSpec)`（Unit → EngineeringUnits、EURange 屬性；AnalogItemType）、`SetValue`、`SetDataValue`、`Value`、`OnWrite`、`RemoveNode`（連帶刪除子節點）、`Stats`、`ListenAddress`、`RegisterHandler`。
- 測試：`tests/go` 的伺服器 fixture 改用新 API；`tests/server` 刪除兩個只針對舊 MapNamespace 的測試，其餘改用新 API；`tests/session` 一個用戶端測試改為明確提供多個 UserName policy；刪除 `examples/server*`。
- **T7 換金鑰**（`uasc/server_tokens.go`）：伺服器每次 OpenSecureChannel（Issue 或 Renew）建立新的 instance 並發新 TokenId（上游重用同一 instance 與 TokenId，且在讀到 Renew 時立即替換金鑰，`algo` 有 data race）。新 token 在用戶端第一次用它的訊息驗簽成功後才用於送出；收到的訊息依 TokenId 選擇金鑰；token 於 lifetime × 1.25 後失效（`BadSecureChannelTokenUnknown`），最新 token 過期未換新則關閉通道。Lifetime 修正到 1 秒～1 小時。
- **T13 OPN 檢查**：Issue 只能在通道尚未開啟時、Renew 只能在開啟後（`BadRequestTypeInvalid`）；Renew 時 SecureChannelId、原則、模式、用戶端憑證不可改變；ReceiverCertificateThumbprint 必須是伺服器憑證；ClientNonce 長度須符合原則（`BadNonceInvalid`）。
- **T8 Hello/Ack 協商**（`uacp`、`uasc`）：Hello 的緩衝區小於 8192 拒絕；ACK 的 ReceiveBufSize / SendBufSize 取雙方較小值；記錄用戶端的 MaxMessageSize / MaxChunkCount，回應超過時改送 `BadResponseTooLarge` 的 ServiceFault（並退回已取用的 SequenceNumber，避免序號跳號）。
- **用戶端**：`DefaultDialer` 改用 `uacp.DefaultClientACK` 的副本；上游的 `MaxMessageSize`、`ReceiveBufferSize` 等選項會改到全域預設值，影響同一程式中之後的所有用戶端。
- **T15**：確認非對稱 ExtraPadding 收送一致（送出端看對方金鑰長度、接收端看自己金鑰長度），新增 2048 / 4096 位元金鑰 × 五種原則 × Sign / SignAndEncrypt 的測試（Basic128Rsa15、Basic256 依規範只允許 ≤ 2048 位元）。
- 新增 X509 使用者憑證登入測試。

### P2：方法與事件
- **Call（S7）**：`AddMethod(object, MethodSpec)`（含 InputArguments / OutputArguments 屬性）、`SetMethodHandler`（例如 ns0 標準方法）。呼叫時檢查物件與方法存在、方法是該物件或其型別（含父型別）的元件（否則 `BadMethodInvalid`）、Executable / UserExecutable、依 InputArguments 檢查參數數量（`BadArgumentsMissing` / `BadTooManyArguments`）與型別（逐一回 `InputArgumentResults`，整體 `BadInvalidArgument`；數值可放寬轉換）；handler 受逾時限制、panic 不影響伺服器。
- **事件（S8）**：`FireEvent(*Event)`；事件沿反向 HasEventSource / HasNotifier 傳到上層通知者，Server 物件收到所有事件。`ObjectSpec.EventNotifier` 讓物件成為通知者。事件型監控項目：EventFilter 先驗證再使用（每個 select clause、where clause 的運算子、運算元數量、ElementOperand 只能往後參照以保證會結束），不合法回 `BadEventFilterInvalid` 與 EventFilterResult。支援運算子：Equals、IsNull、GreaterThan、LessThan、GreaterThanOrEqual、LessThanOrEqual、Like、Not、Between、InList、And、Or、OfType；其他回 `BadFilterOperatorUnsupported`。Select 依事件型別階層判斷（clause 的型別不是事件型別的父型別時回 null）；ConditionId 以 NodeId 屬性、空路徑選取。

### P3：警報（Alarms & Conditions）
- `SetAlarm(Alarm{Source, Name, Type, Message, Severity, Active, Time})`：第一次啟動時建立條件節點（AlarmConditionType 或其子型別的實例，`<來源>.Condition.<名稱>`，來源以 HasCondition 參照），之後每次狀態、訊息或嚴重度變化發出事件。事件欄位：ConditionId（NodeId 屬性、空路徑）、ConditionName、ConditionClassId/Name、BranchId（null）、Retain、EnabledState、Quality、LastSeverity、Comment、ClientUserId、ActiveState（含 Id、TransitionTime、EffectiveDisplayName）、AckedState（含 Id、TransitionTime）。從未啟動過的警報不發事件；不活動且已確認的警報不再保留。
- 標準方法：Acknowledge（檢查 EventId 是最新事件的、尚未確認；`OnAcknowledge` 回呼可拒絕，只會收到能成功的確認；記錄 Comment 與使用者）、ConditionRefresh、ConditionRefresh2（以 RefreshStart / RefreshEnd 事件包住目前保留中的條件，只送給該訂閱或監控項目）。ConditionRefresh 不改變狀態，匿名使用者也可呼叫（方法的 `readOnlyCall`）；Acknowledge 匿名不可呼叫。
- `Alarms()`、`AcknowledgeAlarm()`（應用程式自己確認，例如從自己的畫面）。
- Handler 的 context 帶 session（`sessionFrom`），方法可取得呼叫者的 session。
- 不做：Shelve、Confirm、AddComment、Enable / Disable、Branch（依計畫）。

### P4：歷史
- `SetHistory(HistoryReader)`：應用程式提供 `ReadRaw`、`ReadAtTime`、`ReadEvents`；伺服器負責協定部分：權限（變數須 Historizing 且 AccessLevel 有 HistoryRead，使用者須有 HistoryRead 權限，否則 `BadHistoryOperationUnsupported` / `BadNotReadable` / `BadUserAccessDenied`）、時間參數檢查（`BadInvalidTimestampArgument`）、每節點每次最多 10000 筆並以 session 範圍的 continuation point 分頁（可 Release、有數量上限）、TimestampsToReturn、歷史事件的 EventFilter（select 與 where）。`ObjectSpec.EventHistory` 讓物件可讀歷史事件；設定 HistoryReader 後 Server 物件也可。
- 不做：ReadModified、HistoryUpdate。

### P4b：歷史聚合（Processed）
- `ReadProcessedDetails`：Average、Minimum、Maximum、Count、Start、End（OPC 10000-13）；其他聚合回 `BadAggregateNotSupported`。應用程式不用多實作什麼：伺服器用 `ReadRaw` 取原始值自己算。
- 區間：由 StartTime 往 EndTime 切，EndTime 不含在內；StartTime 晚於 EndTime 時倒著切、結果由新到舊；ProcessingInterval 0 為整段一個區間；最後一段不滿一個區間時狀態碼加 Partial 位元。
- 狀態碼：壞值不參與計算；AggregateConfiguration 的 TreatUncertainAsBad、PercentDataGood、PercentDataBad 依**筆數**比例判定 Good / Uncertain_DataSubNormal / Bad（規範以時間加權，這裡簡化）；UseServerCapabilitiesDefaults 時為 true / 100 / 100。Average、Count、Minimum、Maximum 加 Calculated 位元，最小 / 最大值出現多次加 MultiValue；Minimum、Maximum、Start、End 的時間戳為該原始值的時間。區間內沒有資料：Count 回 0，其餘回 `Bad_NoData`。
- 參數檢查：AggregateType 數量與節點數不同回 `BadAggregateListMismatch`；StartTime 等於 EndTime 或 ProcessingInterval 為負回 `BadInvalidArgument`；任一時間為零回 `BadInvalidTimestampArgument`；百分比大於 100 回 `BadAggregateConfigurationRejected`。
- 每次最多回 10000 個區間，其餘以 continuation point 分頁；原始值以串流方式讀取，記憶體只與區間數有關。
- 位址空間：`ServerCapabilities/AggregateFunctions` 與 `HistoryServerCapabilities/AggregateFunctions` 以 Organizes 列出支援的聚合；`HistoryServerCapabilities` 的各項能力有值。
- `uatool history`：讀 Raw 或聚合值，供現場檢查。

### P5：用戶端
- **`ua` 編碼**：nil 的結構指標編碼為零值結構（上游什麼都不寫，後面的欄位全部錯位，伺服器解碼失敗而關閉通道；例如 `&ua.QueryFirstRequest{}`、`ReadProcessedDetails` 未設 AggregateConfiguration）。
- **`uasc` 用戶端**：收到 ERR 時，所有等待中的請求都收到該狀態碼（上游只得到 EOF，看不到伺服器拒絕的原因）。
- **新套件 `client`（§5.2）**：`Dial(ctx, endpoint, Options)`：`Auto(MinSign|MinSignAndEncrypt)` 選安全等級最高且不低於下限的端點，找不到就回錯誤，**不會降級成 None**；`Explicit(policy, mode)`；`NoSecurity()` 必須明確指定。`Anonymous()` / `UserPass()` / `Cert()`；端點必須提供該登入方式。可設 `TrustStore` 驗證伺服器憑證；未提供用戶端憑證時自動產生自簽憑證。`ReadMany`（每個節點各自的結果，格式錯誤或不存在的 NodeId 只影響自己；依伺服器 MaxNodesPerRead 分批）、`WriteAuto`（讀一次 DataType 並快取，數值 / Boolean / 數字字串自動轉型並檢查範圍；抽象型別改依目前值的型別；伺服器拒絕時錯誤包含狀態碼）、`Subscribe`（每個節點的建立結果、回呼）、`Browse`（自動 BrowseNext）、`State()`（連線狀態事件，自動重連）、`Endpoint()`、`Close()`。不會 `panic` / `log.Fatal`。
- **伺服器修正**：寫入資料型別為 BaseDataType 的變數一律回 `BadTypeMismatch`（`builtinOf` 判斷順序錯誤）。

### P6：交付
- `cmd/demoserver`：模擬伺服器（點數、更新間隔可設；帳號 admin / viewer；警報、事件、方法、記憶體歷史；PKI 目錄；每段時間記錄連線數、session、訂閱、goroutine、記憶體），供 UaExpert 等互通與長時間測試。
- `cmd/uatool`：browse、read、write、subscribe、stress（N 個用戶端 × M 點訂閱，統計每秒通知數）；`-pki` 保存工具自己的憑證，讓伺服器只需信任一次。
- `certs`：使用者刪除 PKI 子目錄時自動補建（被拒絕的憑證原本會默默存不進去）。
- README 改寫；新增 `interop/RESULTS.md`（自動化結果、負載測試、UaExpert 手動清單）；plan.md 更新進度與實際 API。

### 專案整理（2026-11-24）
- 刪除 gopcua 專屬檔案：`gopher.png`、`logo/`（上游贊助商）、上游 `CHANGELOG.md`、`.goreleaser.yml`、`examples/`（低階用戶端範例；用法改看 README、`cmd/demoserver`、`cmd/uatool`）、根目錄空殼 `server.go`（`opcua.Server` 沒有任何功能，伺服器在 `server/`）。
- 文件集中到 `docs/`：`CHANGES.md`、`interop.md`（原 `interop/RESULTS.md`）；`plan.md` 留在根目錄。
- 新的 `CHANGELOG.md` 只記本專案的版本；`SECURITY.md` 改為向本 repo 擁有者私下回報；`LICENSE` 加上本專案的版權行（gopcua 的版權聲明照 MIT 規定保留）；`Makefile` 移除 goreleaser 與 examples 目標。
- 原始檔的 gopcua 版權檔頭（`Copyright 2018-2020 opcua authors`）照 MIT 規定保留，不修改。
- 第二輪（2026-11-24）：
  - `go.mod` 移除沒用到的 `google/uuid`、`golang.org/x/term`、`golang.org/x/sys`（原本給 examples 用），以及上游的 `retract` 區塊（那些是 gopcua 的版本號）。`cmd/id` 改用標準庫 `maps` / `slices`，去掉 `golang.org/x/exp`；順便改為排序後輸出，上游用 map 走訪順序，每次重新產生的檔案都不一樣。現在只剩測試用的 `testify`。CI 加上 `go mod tidy -diff` 檢查。
  - 刪除 `Makefile`：CI 直接寫 `go test` 指令；fuzz 改用 `scripts/fuzz.sh`；程式碼產生用 `go generate ./...`。
  - 根目錄低階用戶端的預設身分從 gopcua 改為 `urn:opcua:client` / `urn:opcua` / `opcua client`（與 `client` 套件一致），預設 session 名稱 `opcua-<時間>`；expvar 名稱 `gopcua` 改為 `opcua`。
  - 刪除沒有被引用的 `ua/uadoc.md`。
- 文件雙語化（2026-11-24）：`README`、`SECURITY`、`CHANGELOG`、`tests/README` 各有繁中（`X.md`）與英文（`X.en.md`）兩份。`tests/` 底下 12 份上游風格的英文說明（各子資料夾的 README 與 NOT-TESTED）合併重寫成 `tests/README.md` 一份，刪掉已過時的內容（MapNamespace、已刪除的測試、上游 PR 流程）。測試程式註解中指向這些舊文件或舊檔案行號的地方一併改寫。`plan.md`、`docs/CHANGES.md`、`docs/interop.md` 是內部工作紀錄，維持只有中文。
- 測試工具獨立（2026-11-24）：`cmd/demoserver`、`cmd/uatool` 移到新專案 uatester（Windows 桌面版＋命令列版 `uatest`），本 repo 只留程式庫本身。`docs/interop.md` 的指令改為 `uatest`。

### 發布前補齊（2026-11-24）

#### 用戶端與伺服器功能對應
- `client` 新增：`Attributes`（節點屬性與使用者權限）、`Translate`（TranslateBrowsePathsToNodeIds）、`ServerStatus`、`Namespaces`、`Endpoints`（連線前列出端點與登入方式）、`MethodArguments` 與 `Call`（依方法的 InputArguments 自動轉型，伺服器拒絕時回 `*CallError`，含每個參數的狀態碼）、`SubscribeEvents`／`EventSubscription.Refresh`（ConditionRefresh）／`Acknowledge`、`HistoryRaw`／`HistoryAtTime`／`HistoryProcessed`／`HistoryEvents`（自動跟隨 continuation point，提早結束時釋放）、`SubscribeWith`（絕對／百分比 deadband、佇列大小、丟棄策略、取樣間隔、觸發條件）。
- **伺服器修正**（`server`）：
  - 事件往上傳遞改為沿所有反向階層參照（HasComponent、Organizes、HasNotifier、HasEventSource），區域物件會收到底下點位的事件與警報。之前只沿 HasEventSource／HasNotifier，加在區域物件底下的點位警報只會到 Server 物件。
  - ConditionRefresh 只送該監控項目所屬通知者範圍內的條件（RefreshStart／End 照送）；之前會把所有條件都送出。
  - ConditionRefresh 重送條件的最後一個事件，EventId 不變。之前每次 Refresh 都產生新的 EventId，一個用戶端做 Refresh 後，其他用戶端手上的 EventId 失效，確認警報會被拒絕（`BadEventIdUnknown`）。

#### 公開
- repo 改為公開。內部開發計畫 `plan.md` 不再放進 repo（`.gitignore`），只留在開發者本機；上面紀錄中提到的 `plan.md` 指的就是它。README 與 SECURITY 改為公開專案的說法（不需 GOPRIVATE；漏洞用 GitHub 私下回報）。

## 未發版

- `server.Server.AddReference(source, refType, target)`：在兩個已存在的節點之間加參照與反向參照；refType 必須是 ReferenceType 節點。MBController 用它保留舊的 `Objects/Data` 入口，以 Organizes 指向新結構裡的同一批點位節點。
