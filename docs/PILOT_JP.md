# SentinelLocal v1.2 個人PC試験運用ガイド

**Windows専用です。対象はWindows PC 1台です。** Defenderを防御基盤として使う試験版です。市販製品と同等の検出率、独立したEDR、カーネルでの自己防御は保証しません。

このガイドの相対コマンドは配布フォルダーで実行する例です。ソースリポジトリから実行する場合、操作用スクリプトにはscripts/の接頭辞を付けてください。設定の初期値はconfig/Config.jsonにあります。[構成・開発ガイド](REPOSITORY_JP.md)で配布作成とソースからの実行方法を説明しています。

## 設定を変えずに診断

Windows PowerShell 5.1で実行します。確認する権限がない場合はUnverifiedになり、「無効」とは区別します。セキュリティ設定、再起動、スキャン、通信リスナーの追加は行いません。

~~~powershell
.\Test-SentinelReadiness.ps1 -OutputPath .\readiness.json
~~~

## 配布パッケージの検証と導入

通常は署名付きpackageと独立して信頼したBootstrap、署名者pinを使います。READMEの導入手順と[セキュリティ修正・制限](SECURITY_JP.md)を参照してください。

署名なし開発版は、レビュー済みソースからflat packageを作成し、別の信頼できる経路で確認したmanifest hashを指定します。未信頼フォルダのmanifestだけから計算したhashでは改変者を認証できません。

~~~powershell
# 信頼・レビュー済みのソースcheckoutで実行する開発者用操作
.\scripts\New-SentinelPackage.ps1 -OutputDirectory ..\SentinelLocal-package
# $reviewedManifestHashは独立に確認したSHA256の64桁
& 'C:\TrustedTools\Bootstrap.ps1' -PackageRoot 'C:\Downloads\SentinelLocal-package' -Mode Verify -DevelopmentUnsigned -ExpectedManifestSHA256 $reviewedManifestHash
# 管理者Windows PowerShellで保護stagingから導入
& 'C:\TrustedTools\Bootstrap.ps1' -PackageRoot 'C:\Downloads\SentinelLocal-package' -Mode Install -DevelopmentUnsigned -ExpectedManifestSHA256 $reviewedManifestHash
~~~

更新はMode Upgradeです。既存導入先やstaging親にreparse・危険なACLがあればBootstrapは拒否します。ACLを緩めて回避しないでください。署名検証の失効確認・タイムスタンプは未対応です。Bootstrap自体の信頼が必要です。実際のコード署名証明書を持つ配布者はBootstrapOutputPathで別出力・Authenticode署名できます。現在の開発版には製品署名は付いていません。

## 状態と調査レポート

~~~powershell
& 'C:\ProgramData\SentinelLocal\Show-SentinelStatus.ps1'
& 'C:\ProgramData\SentinelLocal\Export-SentinelReport.ps1' -OutputDirectory C:\PrivateReports\Sentinel-20260928
& 'C:\ProgramData\SentinelLocal\Export-SentinelReport.ps1' -OutputDirectory C:\PrivateReports\Sentinel-filtered -Search 'パスやPIDやRequestId'
~~~

HTMLとJSONで取得時点の状態、ログ検証結果、最大1000件の時系列を保存します。HTMLは外部通信・スクリプトを使わず、記録内の文字列をHTMLとして実行しません。全履歴分析や攻撃の自動判定ではありません。パス、コマンドライン、通信先などを含み得るため、公開リポジトリや公開フォルダーに保存しないでください。

## 設定の保存・復元

変更ファイルには変更するキーだけを記述します。未知のキーやVersionの変更は拒否します。コードの改変を設定変更に紛れて承認しません。

~~~json
{"Resources":{"MaxEvidenceMB":1024},"Scheduling":{"NormalAgingSeconds":120}}
~~~

~~~powershell
& 'C:\ProgramData\SentinelLocal\Set-SentinelPolicy.ps1' -PolicyPath .\policy.json -Reason '容量調整' -WhatIf
& 'C:\ProgramData\SentinelLocal\Set-SentinelPolicy.ps1' -PolicyPath .\policy.json -Reason '容量調整' -RestartTasks
& 'C:\ProgramData\SentinelLocal\Set-SentinelPolicy.ps1' -RestoreBackupPath 'C:\ProgramData\SentinelLocal\backups\policy-....json' -Reason '設定復元' -RestartTasks
~~~

保存・操作記録に失敗した場合は設定と基準を元に戻します。設定復元は同じコード版に限ります。設定と基準は別ファイルなので、保存中に整合性監視の一時警告が出る可能性があります。バックアップは自動削除せず、不要になったものは運用者が整理します。

## Defenderの段階的な強化

~~~powershell
& 'C:\ProgramData\SentinelLocal\DefenderHardening.ps1' -Profile AuditFirst -WhatIf
& 'C:\ProgramData\SentinelLocal\DefenderHardening.ps1' -Profile AuditFirst
& 'C:\ProgramData\SentinelLocal\DefenderHardening.ps1' -Profile RecommendedBlock -WhatIf
~~~

AuditFirstでは、既存のASR Block/Warn、通信遮断、強いクラウド設定を弱めません。未設定の通信保護・ASR・フォルダー保護は監査にします。ただしPUA、リアルタイム、クラウド保護などは有効化するため、完全な診断専用ではありません。クラウド保護・安全なサンプル送信ではMicrosoftへデータを送信します。

旧設定のDefenderHardening.ApplyOnInstallは互換性のため保持しますが、v1.2のインストーラーでは使用しません。強化設定は上記の専用コマンドで別に適用します。

適用前にバックアップし、適用後の読み戻し・操作記録を残します。改ざん防止、GPO、他のAV、対応状況などで拒否・上書きされた変更を成功と表示しません。失敗時はバックアップを確認し、必要ならRestore-DefenderBackup.ps1を使います。

Network Protectionは、Microsoftが示すPro/Enterpriseクライアントの対応条件を満たす場合だけ適用します。Windows 11 Home、対応不明のエディション、ServerではUnavailableとして省略し、適用済みと表示しません。設定の読み戻し一致は防御効果の実証ではありません。[対応条件](https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection#prerequisites)を確認してください。

## 容量と取りこぼし

- キュー上限5000件、そのうちHigh用100件を確保。満杯の場合は永続化の比較基準・イベントログカーソルを進めず再試行します。CIMプロセス起動イベントは再生できず、過負荷時の検知漏れはあり得ます。
- 通常要求が120秒以上待ち、Highを5件連続処理したら通常要求を1件選びます。処理中への割り込みはしません。
- 最小空き容量512MB、証跡の目安上限2GB、ログ1ファイルの目安上限64MB。5秒の容量キャッシュや並行書き込みにより上限を少し超える可能性があります。全ディスク容量を強制制限する仕組みではありません。
- 容量不足で証跡を勝手に削除しません。失敗・異常を可能な範囲でApplicationログにも記録します。外部保全・保持期間の整理が必要です。
- 停止中の永続化変更は前回の保存状態と比較します。取得・記録・キュー作成失敗時は基準を更新しません。初回は空の状態から一覧を取得します。
- 短時間で終了したプロセスの取得漏れを記録。既存のSysmonを有効にすると保存済み情報を利用できます。導入・設定変更は自動では行いません。

## 実機受け入れ試験と今後

破棄可能なWindows 11 VMで、導入、通常アプリ、再起動、更新成功・失敗と復元、設定復元、Defender公式デモ、アンインストールを確認してください。その後1台で負荷・誤検知・容量を継続観測します。コードのCIと実際のDefenderスキャン・管理者導入は別の検証です。結果が揃うまでは「企業製品と同等」と評価しません。

今後必要なのは安定した常駐サービス、署名付き配布と鍵管理、認証・権限を持つ複数端末管理、攻撃の関連付け、独立した評価です。今回の1台向け試験版では未実装です。

技術はPowerShellに限定しません。次の常駐基盤ではC#のWindowsサービスとイベント収集APIを候補とし、画面・保存・管理機能は必要に応じて別の技術を選びます。カーネルドライバーは署名・互換性・障害時の検証が揃った段階で検討します。現版の常駐処理はWindows PowerShell 5.1とタスクスケジューラです。

参考：[ASR導入の公式手順](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment)、[Windowsドライバーの署名要件](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-)。
