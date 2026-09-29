# リポジトリの構成と開発手順

Windows専用です。リポジトリのルートにはREADME、変更履歴、Gitの設定ファイルを置きます。

| 配置 | 役割 |
| --- | --- |
| bootstrap/ | payloadとは独立して信頼・署名する導入Bootstrap |
| src/ | Watcher、Response、Worker、整合性監視と共通ライブラリ |
| scripts/ | インストール・更新・アンインストール、診断、設定変更、状態画面、配布作成 |
| config/Config.json | 配布時の初期設定 |
| docs/ | 日本語説明書、運用・試験運用・構成ガイド |
| tests/ | 回帰試験と補助スクリプト |
| .github/workflows/ | Windows CI |

## ソースから診断と試験を実行

リポジトリのルートを作業フォルダーとして、Windows PowerShell 5.1で実行します。

~~~powershell
.\scripts\SelfTest-SentinelLocal.ps1 -Root . -PreStart
.\tests\Run-Tests.ps1
.\tests\Run-PilotTests.ps1
.\tests\Run-SecurityTests.ps1
.\scripts\Test-SentinelReadiness.ps1
~~~

テストは一時フォルダーとモックを使用します。実際の導入・Defenderスキャンは別の受け入れ試験です。運用スクリプトのRootは、既定ではC:\ProgramData\SentinelLocalを指します。src/の監視処理をソースリポジトリ自体に対して常駐実行する構成ではありません。

## 配布を作る

出力先には新しいフォルダーを指定します。ソースの内側への出力と上書きを拒否します。

~~~powershell
.\scripts\New-SentinelPackage.ps1 -OutputDirectory ..\SentinelLocal-package
# 検証・導入は独立して信頼したBootstrapを使います。PILOT_JP.md参照。
~~~

配布フォルダーではPS1とConfig.jsonをルートに集めます。説明書は同梱し、docs/のガイドを保ちます。既存のSYSTEMタスク、Root引数、整合性基準、更新・復元のファイル名はこの配置を使用します。署名なし試験版の検証には明示的な許可が必要です。署名の制限はPILOT_JP.mdに記載しています。

導入・更新は独立Bootstrapでflat packageを検証し、保護stagingから行います。payloadのinstaller/upgradeは直接実行しません。

## コードを追加する場合

配布対象はsrc/Common.ps1のGet-SentinelCriticalFileNamesとbootstrap/Bootstrap.ps1のrequired一覧へ登録します。監視や共通コードをsrc/へ追加した場合はGet-SentinelSourcePathのruntime一覧にも登録します。操作用PS1はscripts/に解決されます。配布対象を確認する試験、配布作成、導入前チェックを実行してからPRを作成してください。

logs/、state/、evidence/、backups/、reports/などの実行時データはGitの対象外です。個人の診断結果や調査レポートをコミットしないでください。
