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
| tools/evaluation/ | 試験結果のオフライン集計。常駐処理と配布payloadには含めない |
| .github/workflows/ | Windows CI |

## ソースから診断と試験を実行

リポジトリのルートを作業フォルダーとして、Windows PowerShell 5.1で実行します。

~~~powershell
.\scripts\SelfTest-SentinelLocal.ps1 -Root . -PreStart
.\tests\Run-Tests.ps1
.\tests\Run-PilotTests.ps1
.\tests\Run-SecurityTests.ps1
.\tests\Run-EvaluationTests.ps1
.\tests\Run-EvaluationReadinessTests.ps1
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

## 公開版と配布物

現在の公開パッケージは[v1.2.1-preview.1](https://github.com/kukukucode/SentinelLocal/releases/tag/v1.2.1-preview.1)です。Windows PowerShell 5.1とMicrosoft Defenderを使う、Windows PC 1台向けの試験版です。実行時のVersionは1.2.1で、公開タグのpreview.1は配布の識別子です。

### Releaseの添付ファイル

| ファイル | 用途 |
| --- | --- |
| SentinelLocal-v1.2.1-preview.1-windows.zip | PS1とConfig.jsonをルートに集めた導入用flat package。docs/も同梱 |
| Bootstrap.ps1 | payloadとは別にレビュー・信頼を確認する導入Bootstrap。ZIPには含めない |
| package.manifest.json | ZIP内の各ファイルのSHA256・長さを確認するmanifest。ZIP内にも同じものを含む |
| release-metadata.json | 公開タグ、ソースコミット、実行時Version、署名の有無、配布物のハッシュ |
| SHA256SUMS.txt | 添付ファイルのSHA256一覧 |

GitHubが自動生成するSource code ZIP / tar.gzはソースcheckout用です。src/・scripts/・config/に分かれており、導入用flat packageとは異なります。ソースからの配布作成は[構成ガイド](REPOSITORY_JP.md)を参照してください。Sysmonのバイナリは添付しません。Sysmonは任意で、[運用ガイド](OPERATIONS_JP.md)の確認手順に従って別途準備します。

### 検証と導入

この試験版には製品用のCMS署名・BootstrapのAuthenticode署名を付けていません。存在しないsigner pinを指定する必要はありません。署名なし開発版の導入には、独立して信頼を確認したBootstrapとmanifestのSHA256、明示的なDevelopmentUnsignedが必要です。

ハッシュ一覧は配布物の整合性確認に使います。同じ未信頼のダウンロード元から得たZIP・Bootstrap・ハッシュが一致するだけでは、配布元の真正性を証明しません。公開タグのソースとBootstrapをレビューし、信頼する経路で確認した値を使ってください。具体的なVerify / Install / Upgradeの手順は[個人PC試験運用ガイド](PILOT_JP.md)にあります。

配布payloadのInstall-SentinelLocal.ps1 / Upgrade-SentinelLocal.ps1を直接実行しません。独立したBootstrapが検証後に管理者/SYSTEMだけのstagingへコピー・再検証してから実行します。ダウンロードやReleaseの更新だけでは、端末の既存インストールは変更されません。

### 試験結果と既知の制限

2026-10-04にhostname・whoami・cmdのechoを各10回実行した結果です。

| 項目 | 結果 |
| --- | --- |
| Sysmon原本のプロセス取得 | 30/30。PID・パス・SHA256・生成時刻・引数・一意のGUIDを照合 |
| Sentinelへの120秒以内の保存 | 0/30 |
| 起動からSysmon記録まで | 中央値7.733ms、p95 24.308ms、最大32.063ms |
| Sentinelの取り込み遅延 | 追加収集時点で処理中のイベントが約31分前 |
| マルウェア検知率・誤検知率・検知時間・ATT&CK coverage | 未測定 |

Heartbeatが正常でもイベント取り込みが遅れる課題が残っています。ログは既定で30日保持・1ファイル約64MB上限ですが、容量による自動ローテーションは未整備で、上限到達時に記録を拒否します。計測用Tempコピーは運用ログの自動保持処理の対象外です。

改善は[取り込み速度 #6](https://github.com/kukukucode/SentinelLocal/issues/6)、[滞留監視 #7](https://github.com/kukukucode/SentinelLocal/issues/7)、[ログ容量 #8](https://github.com/kukukucode/SentinelLocal/issues/8)を優先し、[処理時間調査 #9](https://github.com/kukukucode/SentinelLocal/issues/9)、[状態表示 #10](https://github.com/kukukucode/SentinelLocal/issues/10)、[Temp整理 #11](https://github.com/kukukucode/SentinelLocal/issues/11)、[評価拡大 #12](https://github.com/kukukucode/SentinelLocal/issues/12)で追跡します。これらの改善をこのReleaseで完了したとは扱いません。

CIにはWindows Server 2022 / 2025のPowerShell 5.1回帰試験と、破棄可能なVMで実Sysmonを使う統合試験があります。CI成功は実PCのリアルタイム性やマルウェア防御性能の合格を意味しません。評価手順は[評価ガイド](EVALUATION_JP.md)を参照してください。

### 旧版

v1.0.0のRelease・タグ・配布物は参照用に保持します。新しいBootstrapと信頼境界の修正を含まない旧版なので、新規導入には使用しないでください。公開された試験版のコードを調べる際は、既定ブランチではなく対応する公開タグとrelease-metadata.jsonのコミットを照合してください。
