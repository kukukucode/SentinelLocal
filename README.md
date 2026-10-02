# SentinelLocal v1.2.1

[![Windows CI](https://github.com/kukukucode/SentinelLocal/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/kukukucode/SentinelLocal/actions/workflows/windows-ci.yml)

**SentinelLocalはWindows専用のツールです（Windows only）。**
Microsoft Defender、Windowsのタスクスケジューラ、イベントログ、Windows Firewallを利用します。LinuxやmacOSには対応していません。

Microsoft Defenderを主防御エンジンとして利用する、軽量Host IDS / Defender補助コントローラーです。疑わしい対象をDefender Custom Scanへ渡し、Defenderの判定を優先します。独自アンチウイルス、Protected Process、カーネルEDRではありません。

## リポジトリ構成

| フォルダー | 内容 |
| --- | --- |
| src/ | 監視・応答処理と共通コード |
| scripts/ | 導入・更新・診断・設定・状態画面の操作用スクリプト |
| config/ | 初期設定のConfig.json |
| docs/ | 日本語説明書と運用・開発ガイド |
| tests/ | 回帰試験とテスト補助コード |
| tools/evaluation/ | 防御性能の試験結果を集計する開発用ツール |
| .github/ | Windows CI |

ソースから使う場合はscripts/のスクリプトを実行します。New-SentinelPackage.ps1で作る配布パッケージとインストール先は従来の配置を使用します。[構成・開発ガイド](docs/REPOSITORY_JP.md)を参照してください。

## 動作環境

- Windows
- Windows PowerShell 5.1（`powershell.exe`）
- Microsoft Defenderと関連するPowerShellコマンドレットが利用できる環境
- インストール、更新、Defender設定変更、保護されたログの閲覧を行うための管理者権限

## バージョン

このリポジトリの初回公開版は **v1.0.0** です。提供された`SentinelLocal-v2.5.zip`を基に、設定・スクリプト・ドキュメントのバージョン表記をv1.0.0に統一しています。

v1.1.0では、スキャン失敗の再試行、ログ削除検知、イベントの取りこぼし対策、応答処理のタイムアウトを追加しました。Windows用の状態画面と通知、期限付き例外、監査ログの外部出力、別PCからの死活確認、任意のSysmon連携にも対応しています。設定・運用方法は[運用ガイド](docs/OPERATIONS_JP.md)を参照してください。

現在の **v1.2.1はWindows PC 1台向けの試験運用版** です。内容のハッシュによる再スキャン判定、再起動をまたぐ永続化比較、容量管理、更新の復元・起動確認、読み取り専用の診断、HTML/JSON調査レポート、設定の検証・復元、署名付きパッケージの検証に対応します。[個人PC試験運用ガイド](docs/PILOT_JP.md)を参照してください。

企業製品と同等の防御性能は未実証です。Windows 11での診断・CIと、実際の管理者導入・Defenderスキャン・長期運用の検証は別です。

実マルウェアに対する検知率・正常操作の誤検知率・検知時間・ATT&CKカバレッジは未測定です。[評価ガイド](docs/EVALUATION_JP.md)に、段階的な測定手順と試験結果の入力・集計方法を記載しています。同梱のサンプルは架空データで、製品性能の実測値ではありません。

## 主な機能

- プロセス、永続化、TCP接続、Defenderイベントの監視
- High / Normalの優先Response Queue
- Watcher側のパス・内容・プロセス識別子による重複抑制と、Worker側のSHA-256単位の重複抑制
- JSONLログのSHA-256ハッシュチェーン
- HIGH / CRITICALイベントのWindows Application Event Logへの二重記録
- 自身のタスク、Heartbeat、重要ファイルのハッシュの監視
- Defenderの監査優先設定と、検出確認後の対応
- スキャン結果の状態分離、遅延付き再試行、応答時間の上限とキュー滞留警告
- ログの先頭・末尾・件数・バイト長のローカルチェックポイント照合
- 古い未処理イベントからのバッチ取得と、イベントログの消去・上書き検知
- Windowsの状態画面、利用者が有効化するデスクトップ通知
- SHA-256と期限に結びついた例外、任意の署名者照合
- 外部フォルダー／UNC共有への監査スナップショット出力と、WinRMによる外部死活確認
- 任意のSysmonイベント取り込み（既定OFF）

## インストール

**Windows専用です。管理者Windows PowerShell 5.1で実行します。** 配布payloadとは独立してレビューしたBootstrapをC:\TrustedTools\Bootstrap.ps1へ用意してください。Bootstrap自体とsigner pinを未信頼のDownloadsだけから取得しないでください。

署名付きflat packageの導入例です。$signerPinには別の信頼できる経路で確認したコード署名証明書の拇印40桁を指定します。

~~~powershell
$signerPin = '<独立して確認した証明書の拇印40桁>'
& 'C:\TrustedTools\Bootstrap.ps1' -PackageRoot 'C:\Downloads\SentinelLocal-package' -Mode Verify -TrustedSignerThumbprint $signerPin
& 'C:\TrustedTools\Bootstrap.ps1' -PackageRoot 'C:\Downloads\SentinelLocal-package' -Mode Install -TrustedSignerThumbprint $signerPin
~~~

Bootstrapはpayloadをdot-sourceせずに検証し、管理者/SYSTEMだけのstagingへ検証済みbytesをコピーします。再hash確認後、そのstaging内のinstallerを実行します。配布フォルダのInstall-SentinelLocal.ps1 / Upgrade-SentinelLocal.ps1を直接実行する手順は廃止しました。

現在の開発版には製品用の信頼済み署名はありません。レビューしたソースから署名なしで試す開発手順は[PC試験運用ガイド](docs/PILOT_JP.md)を参照してください。[v1.2.1の修正と制限](docs/SECURITY_JP.md)も確認してください。

導入先の初期値はC:\ProgramData\SentinelLocalです。Watcher、Response Worker、Integrity MonitorのSYSTEMタスクを登録します。通常導入はDefender設定を変更しません。変更計画は次のコマンドで確認します。

~~~powershell
& 'C:\ProgramData\SentinelLocal\DefenderHardening.ps1' -Profile AuditFirst -WhatIf
~~~

## 既存インストールの更新

同じ独立Bootstrapとsigner pinを使います。既存設定を保持し、新しい初期値を追加します。更新失敗時はコード・設定・baseline・タスクを復元します。

~~~powershell
& 'C:\TrustedTools\Bootstrap.ps1' -PackageRoot 'C:\Downloads\SentinelLocal-package' -Mode Upgrade -TrustedSignerThumbprint $signerPin
~~~

## 診断とログ検証

```powershell
& 'C:\ProgramData\SentinelLocal\SelfTest-SentinelLocal.ps1'
& 'C:\ProgramData\SentinelLocal\Check-SentinelLocal.ps1'
& 'C:\ProgramData\SentinelLocal\Verify-SentinelLogs.ps1'
```

各JSONL行には`_ChainAlg`、`_ChainPrev`、`_ChainHash`が記録されます。HIGH / CRITICALイベントは、WindowsのApplicationログにもSource=`SentinelLocal`、Event ID=`1902`として記録されます。

## 設定と自己監視

`Config.json`で監視間隔、応答方針、Defender設定、自己監視などを設定します。

Response Queueはスコア80以上をHigh、40以上80未満をNormalとして扱い、Highを優先します。既定の重複抑制期間はパス・内容単位で300秒、SHA-256単位で600秒です。実行中プロセスに紐づく要求とHigh Risk要求は、SHA-256の重複でも処理します。

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
& 'C:\ProgramData\SentinelLocal\Uninstall-SentinelLocal.ps1'

# データも削除する場合
& 'C:\ProgramData\SentinelLocal\Uninstall-SentinelLocal.ps1' -RemoveData
```

詳細は[日本語説明書](docs/README_JP.txt)と[変更履歴](CHANGELOG.txt)を参照してください。

## CIと回帰テスト

GitHub ActionsでWindows Server 2022 / 2025のWindows PowerShell 5.1を使用し、構文解析、パッケージの導入前チェック、回帰テストを実行します。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-PilotTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-EvaluationTests.ps1
```

テストは一時フォルダーとモックを使用します。Defenderの実スキャン、インストール、OS設定変更は行いません。Windowsの実機・VMでのインストール後の検証は別途必要です。
