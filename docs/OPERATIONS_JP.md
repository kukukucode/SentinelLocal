# SentinelLocal v1.1 運用ガイド（Windows専用）

管理者として起動したWindows PowerShell 5.1を使用してください。以下の例のインストール先は`C:\ProgramData\SentinelLocal`です。

## 応答処理と再試行

Defenderスキャン開始や結果取得、証拠保存に失敗した場合、応答処理は失敗をWorkerへ返します。失敗した依頼はすぐに完了扱いにせず、`ResponseQueueMaxAttempts`（既定3回）の範囲で再試行します。`ResponseRetryDelaySeconds`（既定10秒）を基準に待ち時間を増やします。再試行上限を超えた依頼は`state\response-queue\failed`に移します。

結果は`Completed`、`TargetMissing`、`NoScanRequired`、`Excepted`に分かれます。対象消失やスキャン失敗は「問題なし」の判定ではありません。SHA-256による重複抑制の完了履歴は`Completed`の場合だけ保存します。`Completed`はスキャン呼び出しと結果取得の成功を示し、ファイルの安全性を保証する判定ではありません。

応答は別プロセスで実行し、Workerが進捗Heartbeatを更新します。Highの上限は`ResponseTimeoutSeconds`（既定180秒）、Normalは`NormalResponseTimeoutSeconds`（既定60秒）です。時間超過時は応答プロセスを終了し、依頼を再試行します。既にDefenderサービスで開始したスキャン自体の中止を保証するものではありません。

処理は1件ずつで、次の依頼を選ぶときにHighを優先します。実行中のNormalをHighが割り込んで停止する方式ではありません。キューの最古依頼が`QueueWarningSeconds`（既定120秒）を超える、または件数が`QueueWarningCount`（既定1000件）を超えると警告します。

## ログ検証と保持

```powershell
& 'C:\ProgramData\SentinelLocal\Verify-SentinelLogs.ps1'
```

検証は行ごとのハッシュチェーンと、`state\log-chain`のチェックポイントを照合します。末尾・先頭の削除、ログ全体の削除、件数・長さの変化を検知します。書き込み、保持期間の整理、検証、スナップショット取得は同じ名前付きMutexを使用します。

保持期間の整理は古い行の連続した先頭部分だけを削除し、残ったチェーンの境界をチェックポイントに保存します。時刻の逆行などで途中に古い日時の行がある場合、それだけを削除してチェーンを壊すことはありません。書き込みとファイル置換は保留中トランザクションを記録し、中断後に完了済みの変更を回復します。

v1.0のチェックポイントは末尾ハッシュを確認してから移行します。チェックポイントのない既存ログや、途中で切れたログを自動的に「正常」として再登録する処理はありません。異常時はログ・チェックポイント・`.pending`を保全し、外部のコピーと照合してください。

チェックポイントも同じPC上にあるため、管理者がログとチェックポイントを両方改変する攻撃には独立した証明になりません。外部に保存したコピー、共有のACL、WEFなどと組み合わせてください。

## 状態画面とデスクトップ通知

```powershell
& 'C:\ProgramData\SentinelLocal\Show-SentinelStatus.ps1'
```

画面は5秒ごとに監視コンポーネント、Heartbeat、キュー、Defenderの動作モード、改ざん防止状態、最近の警告を表示します。画面上のチェックボックスでデスクトップ通知を有効にできます。通知は既定OFFで、この画面を開いている間だけ動作します。

SYSTEMの常駐タスクからユーザー画面へ直接通知する処理はありません。ログを読める管理者の対話セッションで画面を起動してください。Windowsの通知設定によりバルーン表示が抑制される場合があります。

## 期限付きの例外

```powershell
& 'C:\ProgramData\SentinelLocal\Add-SentinelException.ps1' `
    -FilePath 'C:\Tools\TrustedTool.exe' `
    -Reason '確認済みの業務ツール' `
    -ExpiresAt '2026-12-31T23:59:59+09:00' `
    -RequireSigner
```

例外はファイルのSHA-256、理由、有効期限に結びつきます。`-RequireSigner`を付けると、現在の有効な署名者の証明書Thumbprintも照合します。署名だけ・フォルダーだけで広く除外する設定はありません。ファイル更新でハッシュが変わるか期限が切れると無効です。

このコマンドは設定変更前のConfig.jsonが既存の整合性基準と一致することを確認し、設定の基準ハッシュだけを更新します。他のファイルを一括で信頼し直す処理はありません。実行後に3つのSentinelLocalタスクを再起動して設定を読み直してください。

例外はヒューリスティックによる追加スキャンを対象とし、Defenderの確認済み検出への対応を無効化しません。また、PowerShell本体の例外は、そのコマンドで参照される別スクリプトの例外にはなりません。

## 外部への監査スナップショット

明示的に指定したフォルダーまたはUNC共有に、JSONLログ、チェックポイント、Heartbeat、SHA-256一覧のマニフェストを出力できます。

```powershell
& 'C:\ProgramData\SentinelLocal\Export-SentinelAudit.ps1' `
    -DestinationPath '\\COLLECTOR\SentinelAudit\PC01'
```

途中のコピーは`.pending-*`フォルダーに作り、完了後に確定フォルダーへ移します。確定フォルダーはそれぞれのログについて整合したコピーですが、複数ログを同一時刻で凍結する方式ではありません。部分的に失敗した`.pending-*`は確定済み証拠として扱わないでください。

別PCまたは保全先で、出力済みコピーを検証できます。

```powershell
& 'C:\Tools\SentinelLocal\Verify-SentinelLogs.ps1' `
    -Root '\\COLLECTOR\SentinelAudit\PC01\確定スナップショット名' `
    -ReferenceManifestPath '\\COLLECTOR\SentinelAudit\PC01\確定スナップショット名\manifest.json'
```

マニフェスト照合は出力したコピーの完全一致を検証します。出力後に追記・保持処理が行われた現行ログに古いマニフェストを適用する用途ではありません。

定期出力を行う場合は`Config.json`の`AuditExport.Enabled`をtrue、`DestinationPath`を共有先、`IntervalSeconds`を30秒以上に設定し、設定を確認して整合性基準を更新した後に、別のPowerShellプロセスで実行してください。

```powershell
& 'C:\ProgramData\SentinelLocal\Export-SentinelAudit.ps1' -Watch
```

既定では定期出力しません。転送先や資格情報は自動設定しません。UNC共有へアクセスできる実行アカウントを使用し、保全先の書き込み・削除権限を運用方針に合わせて設定してください。古い確定スナップショットの保持・削除は保全先で管理します。

Windows Event Forwardingを既に利用している環境では、ApplicationログのSource=`SentinelLocal`、Event ID=`1901`（記録失敗）と`1902`（HIGH/CRITICAL）も収集できます。

## 別PCからの死活確認

監視対象PCとは別のPCから実行します。WinRMと、対象のインストール先を読み取れる認証・権限が必要です。スクリプトはWinRMの有効化や資格情報の保存を自動では行いません。

```powershell
& 'C:\Tools\SentinelLocal\Test-SentinelRemoteHealth.ps1' -ComputerName 'PC01'
```

終了コード0は正常、1は監視・キュー・Defenderに異常、2は接続失敗またはタイムアウトです。外部PCのタスクスケジューラや既存の監視基盤から定期実行すると、監視対象PCの全コンポーネント停止や到達不能も検知できます。通知先のサービスやメール送信は自動設定しません。

## Defenderの動作モード

状態画面とDefenderHealthは`AMRunningMode`、保護有効状態、改ざん防止状態を表示します。Normal以外や保護停止時は保護低下を警告します。PassiveはActiveと同じ保護能力を意味しません。他社製AVや組織の管理ポリシーを勝手に解除する処理はありません。

## Sysmon連携

Sysmonは任意の依存関係です。自動ダウンロード・インストール・設定変更はしません。既に導入・設定済みのSysmonを使用する場合、`Config.json`の`Sysmon.Enabled`をtrueにし、整合性基準を更新してSentinelLocalタスクを再起動してください。

イベント1（プロセス作成）、3（TCP/UDP通信）、19〜21（WMI永続化）、22（DNS）、25（プロセス改変）を`sysmon-events.jsonl`へ取り込みます。通信などのイベントを得るには、Sysmon側でも該当収集を有効化する必要があります。プロセス作成イベントのコマンドラインから、参照されたローカルスクリプトを追加スキャンに渡します。

WMIのプロセス開始通知でも、絶対パスで指定されたps1/psm1/vbs/js/hta/bat/cmdを別の対象としてスキャンします。`ScanReferencedScripts`は既定trueで、ヒューリスティックスコアが低い通常のスクリプトホストでも、参照されたローカルスクリプトをDefenderへ渡します。この追加スキャンは悪意の判定やプロセスの強制終了を意味しません。

PowerShellのEncodedCommandはUTF-16LEとして復号して証拠フォルダーへ保存し、静的スキャンへ渡します。保存した内容は実行しません。相対パスをSYSTEMの作業フォルダー基準で解釈したり、URLから内容をダウンロードしたり、コードを実行して解析したりしません。動的な難読化や遠隔コードの判定はこの機能だけでは完結せず、DefenderのAMSIなどに依存します。

## 検証範囲

回帰テストは、ログ切り詰め・削除・同時書き込み・中断回復、300件超のイベントとログ消去、スキャン失敗の伝播と再試行、タイムアウト、例外の期限とハッシュ、Sysmon取り込み、監査コピー、状態画面の構築を確認します。Defenderの実スキャンや、管理者権限での実インストール・復旧検証を代替するものではありません。
