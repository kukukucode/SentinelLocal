# v1.2.1 セキュリティ修正と制限

**Windows専用・PC 1台向けの試験運用版です。** Microsoft Defenderを防御エンジンとして使います。

| レビュー | 修正 |
| --- | --- |
| P0-1 / P0-3 | 独立BootstrapでCMS・signer pin・hash・reparseを確認。管理者/SYSTEMだけのstagingに検証済みstreamからコピーし再hash。導入子プロセス終了まで共有書き込み/削除を拒否するハンドルを保持 |
| P0-2 | ObservedSHA256を照合。PID・生成時刻が一致するファイル消失/変更はLiveTargetMissing / LiveTargetChanged。HIGH未解決として記録し、キューを成功として削除しない |
| P1-1 | Action 1個、標準PowerShellの絶対パス、引数完全一致、SYSTEM・Highest・ServiceAccount、Boot Trigger 1個。改変タスクを自動再有効化しない |
| P1-2 | 揮発性ProcessStartはfinallyでRemove-Event。FailedObservationを記録し後続へ進む。Sysmonの永続cursorはキュー保存失敗時に進めない |
| P1-3 | Sysmon 25と19–21をHIGH警告。3/22はID1とProcessGuidで相関し、既に疑わしいプロセスへ各5点まで加算。相関cacheは最大1000件・1時間 |
| P1-4 | 環境変数、引用符、LOLBin、exe/dll/ps1/psm1/vbs/js/hta/cmd/batのローカル引数を静的解析。シェル実行・URL取得はしない |
| P1-5 | AutoGlobalRemoveMpThreat=falseを追加。全Active Threat削除は既存の自動対応設定と別の明示許可を両方必要とする |
| P1-6 | baseline作成時の欠落で中止。読み込み時は名前集合・Path・hash形式・重複・不足・余分を検証 |

## 信頼の起点

Bootstrap自体と署名者pinは独立して検証した経路・管理者がレビューした固定版から取得します。配布フォルダのBootstrapを、同じフォルダのmanifestだけで信頼しないでください。Authenticode署名済みBootstrapの別配布に対応するため、New-SentinelPackage.ps1は任意のBootstrapOutputPathへの別出力と、CertificateThumbprint指定時の署名に対応します。実際の信頼済みコード署名証明書は配布者が用意します。現在の開発版に製品用の信頼済み署名は付いていません。

通常導入は署名付きflat packageを使います。署名なし開発版はDevelopmentUnsignedと、別経路でレビューしたExpectedManifestSHA256が必須です。同じ未信頼フォルダからhashを計算するだけではmanifest差し替えを認証できません。BootstrapはCMSのSHA256・pin・コード署名EKU・有効期間を確認します。失効確認・署名タイムスタンプ・巻き戻し防止は未実装です。管理者/SYSTEM・カーネル権限の攻撃者は、この保護の対象外です。

## 証拠と未解決状態

CaptureQueuedFileSnapshot=trueで、観測hashに一致するファイルをevidence/queued/RequestId/payload.binへ保存します。管理者/SYSTEMだけの導入先で作成し、読み取り専用属性と再hashを確認します。MaxSnapshotFileMBは初期値32 MB、全証拠容量はMaxEvidenceMBで制限します。取得前の消失・読み取り失敗・制限超過はHIGHで記録し、キュー処理を続けます。snapshot取得は保証されません。

検証済みsnapshotがあればDefenderへ渡します。元ファイルの消失/変更はsnapshotスキャン成功でも未解決です。スキャン前後にも元ファイルを照合します。未解決結果は再試行後にstate/response-queue/failedへ残ります。failed request、未解決response、queued snapshotは日数で自動削除しません。調査・監査出力後に管理者が整理してください。容量が埋まると新しい証拠取得が停止して警告します。

これはメモリ内コードの無害化や、消失したマルウェアの停止を保証しません。PID再利用や生成時刻を照合できないケースで別プロセスを停止しません。

## 回帰試験と実機確認

Run-Tests.ps1 / Run-PilotTests.ps1 / Run-SecurityTests.ps1をWindows PowerShell 5.1で実行します。Defender・Event Log・Scheduled Taskの実操作はmockです。Windows-2022 / Windows-2025 CIではRun-SecurityTests.ps1 -RequireSecureStagingTestsを必須とし、実ACLでstaging・snapshotを試験します。CI保護フォルダは診断用に残し、使い捨てVMごと破棄します。一般PCでは管理者tokenがなければこの2種類の試験はSKIPされます。

実際のDefenderによるsnapshot検知・隔離、UACによる導入/更新、実際のScheduled TaskのCIM表現、長時間負荷は、実運用前に隔離Windows VMで確認してください。
