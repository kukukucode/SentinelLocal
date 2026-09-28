# SentinelLocal v1.0.0

**SentinelLocalはWindows専用のツールです（Windows only）。**
Microsoft Defender、Windowsのタスクスケジューラ、イベントログ、Windows Firewallを利用します。LinuxやmacOSには対応していません。

Microsoft Defenderを主防御エンジンとして利用する、軽量Host IDS / Defender補助コントローラーです。疑わしい対象をDefender Custom Scanへ渡し、Defenderの判定を優先します。独自アンチウイルス、Protected Process、カーネルEDRではありません。

## 動作環境

- Windows
- Windows PowerShell 5.1（`powershell.exe`）
- Microsoft Defenderと関連するPowerShellコマンドレットが利用できる環境
- インストール、更新、Defender設定変更などを行うための管理者権限

## バージョン

このリポジトリの初回公開版は **v1.0.0** です。提供された`SentinelLocal-v2.5.zip`を基に、設定・スクリプト・ドキュメントのバージョン表記をv1.0.0に統一しています。

## 主な機能

- プロセス、永続化、TCP接続、Defenderイベントの監視
- High / Normalの優先Response Queue
- Watcher側のパス単位の重複抑制と、Worker側のSHA-256単位の重複抑制
- JSONLログのSHA-256ハッシュチェーン
- HIGH / CRITICALイベントのWindows Application Event Logへの二重記録
- 自身のタスク、Heartbeat、重要ファイルのハッシュの監視
- Defenderの監査優先設定と、検出確認後の対応

## インストール

ダウンロードしたファイルを展開し、管理者として起動したWindows PowerShellで、そのフォルダーから実行してください。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-SentinelLocal.ps1
```

既定のインストール先は`C:\ProgramData\SentinelLocal`です。以下のタスクがSYSTEM権限で登録されます。

- SentinelLocal Watcher
- SentinelLocal Response Worker
- SentinelLocal Integrity Monitor

DefenderのAuditFirstプロファイルも適用する場合は、次のように実行します。

```powershell
.\Install-SentinelLocal.ps1 -ApplyDefenderAuditProfile
```

Defender設定はAuditFirstから開始し、業務への影響を確認してからBlockへ進める設計です。

## 既存インストールの更新

既存の設定値を保持して更新する場合は、管理者Windows PowerShellで実行してください。元パッケージの旧v2.4向けキュー移行処理も含まれています。

```powershell
.\Upgrade-SentinelLocal.ps1
```

## 診断とログ検証

```powershell
& 'C:\ProgramData\SentinelLocal\SelfTest-SentinelLocal.ps1'
& 'C:\ProgramData\SentinelLocal\Check-SentinelLocal.ps1'
& 'C:\ProgramData\SentinelLocal\Verify-SentinelLogs.ps1'
```

各JSONL行には`_ChainAlg`、`_ChainPrev`、`_ChainHash`が記録されます。HIGH / CRITICALイベントは、WindowsのApplicationログにもSource=`SentinelLocal`、Event ID=`1902`として記録されます。

## 設定と自己監視

`Config.json`で監視間隔、応答方針、Defender設定、自己監視などを設定します。

Response Queueはスコア80以上をHigh、40以上80未満をNormalとして扱い、Highを優先します。既定の重複抑制期間はパス単位で300秒、SHA-256単位で600秒です。実行中プロセスに紐づく要求とHigh Risk要求は、SHA-256の重複でも処理します。

Integrity Monitorはタスクの削除・無効化・Root引数の改変、Heartbeat、重要PS1と`Config.json`のSHA-256を監視します。基準ファイルは`state\integrity-baseline.json`です。

意図的にコードや設定を変更した場合は、内容を確認したうえで管理者Windows PowerShellから基準ハッシュを更新してください。

```powershell
& 'C:\ProgramData\SentinelLocal\Update-SentinelIntegrityBaseline.ps1'
```

## Firewall

`AutoFirewallBlockOnDefenderConfirmation`は既定でOFFです。ONの場合はGroup=`SentinelLocal`の一時ルールを作成し、期限後に削除します。

```powershell
# ルールの確認
& 'C:\ProgramData\SentinelLocal\Clear-SentinelFirewallRules.ps1' -ListOnly

# SentinelLocalのルール解除
& 'C:\ProgramData\SentinelLocal\Clear-SentinelFirewallRules.ps1'
```

## 制約

- Administrators / SYSTEM / Kernelを完全に奪われた後の自己防御は保証しません。
- ハッシュチェーンは改ざん検出を補助しますが、完全侵害された管理者やSYSTEMからログ自体を守る仕組みではありません。
- 証拠を別ホストで保全する場合は、Windows Event Forwarding（WEF）などでApplicationログのSentinelLocalイベントを転送してください。
- TCPのスナップショットを中心に監視するため、UDP / QUIC / DNSの全量監視やカーネル可視性はありません。
- 基準ハッシュ自体も、管理者やSYSTEM権限を持つ攻撃者の攻撃対象になります。

## アンインストール

管理者Windows PowerShellから実行してください。

```powershell
.\Uninstall-SentinelLocal.ps1

# データも削除する場合
.\Uninstall-SentinelLocal.ps1 -RemoveData
```

詳細は[日本語説明書](README_JP.txt)と[変更履歴](CHANGELOG.txt)を参照してください。
