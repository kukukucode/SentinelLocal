Source repository: operational scripts are under scripts/; defaults are in config/Config.json. See docs/REPOSITORY_JP.md.
v1.2 single-PC pilot: docs/PILOT_JP.md
Install/upgrade unsigned pilot: -AllowUnsignedPackage is now required.
Use DefenderHardening.ps1 separately; the former installer audit-profile switch was removed.

v1.1の追加機能・設定手順は docs\OPERATIONS_JP.md を参照してください。

SentinelLocal v1.2.0（Windows専用）
==================

位置づけ
--------
SentinelLocalはMicrosoft Defenderを主防御エンジンとして利用する軽量Host IDS / Defender補助コントローラーです。
独自アンチウイルス、Protected Process、カーネルEDRではありません。

v1.0.0の重点
----------
1. High / Normalの優先Response Queue
2. Path単位のWatcher-side dedupe
3. SHA-256単位のWorker-side dedupe（High Riskはdedupeで落とさない）
4. JSONLログのSHA-256ハッシュチェーン
5. HIGH / CRITICALイベントのWindows Application Event Log二重記録
6. SentinelLocal自身のTask / Heartbeat / 重要ファイルHashの自己監視
7. Windows Event Forwardingで別ホスト保全しやすい構成

重要な限界
----------
・Administrators/SYSTEMやKernelを完全に奪われた後の自己防御を保証しません。
・ハッシュチェーンは改ざん「検出」を助けますが、同一ホスト上の秘密鍵署名ではないため、
  完全侵害された管理者/SYSTEMからログそのものを守る仕組みではありません。
・本当に消されない証拠が必要なら、ApplicationログのSentinelLocalイベントを
  Windows Event Forwarding (WEF) などで別PC/サーバーへ転送してください。
・TCPのスナップショット中心なのでUDP/QUIC/DNS全量監視やカーネル可視性はありません。

Response Queue
--------------
Score >= ResponseQueueHighScore（既定80）:
  state\response-queue\high

Score >= DefenderCustomScan（既定40）かつ80未満:
  state\response-queue\normal

Workerは常にHighをNormalより先に処理します。

Path/process dedupe:
  ResponseQueueDedupeSeconds（既定300秒）
  プロセス起動要求は Path + PID + CreationDate 単位でdedupeします。
  同じファイルから別PIDが起動した場合を誤って捨てません。
  PersistenceなどPIDのない要求はPath単位です。

SHA-256 dedupe:
  ResponseHashDedupeSeconds（既定600秒）
  PIDのないPersistence/静的要求だけを対象にします。
  実行中プロセスに紐づく要求とHigh Risk要求はSHA-256重複でも処理します。

ログ保全
--------
各 *.jsonl 行には次が追加されます。

  _ChainAlg  = SHA256
  _ChainPrev = 前行のHash
  _ChainHash = 現在行のHash

検証:

  C:\ProgramData\SentinelLocal\Verify-SentinelLogs.ps1

HIGH / CRITICALログはWindows Application Event Logにも
Source = SentinelLocal / Event ID = 1902
として記録します。

自己監視
--------
Scheduled Task:
  SentinelLocal Watcher
  SentinelLocal Response Worker
  SentinelLocal Integrity Monitor

Integrity Monitorは次を監視します。

・上記Taskの削除/Disabled/Root引数改変
・Watcher / Response Worker heartbeat
・重要PS1とConfig.jsonのSHA-256

基準ファイル:
  state\integrity-baseline.json

意図的にConfigやSentinelLocalコードを変更した場合は、内容を確認後:

  C:\ProgramData\SentinelLocal\Update-SentinelIntegrityBaseline.ps1

を管理者PowerShellで実行して基準Hashを更新してください。

注意:
攻撃者が管理者/SYSTEMを持つとbaseline自体も攻撃対象です。
この自己監視はProtected Process相当ではありません。
別ホストへのログ転送と組み合わせることで価値が上がります。

インストール
------------
管理者PowerShell:

  Set-ExecutionPolicy -Scope Process Bypass
  .\Install-SentinelLocal.ps1

Defender AuditFirstも同時に設定:

  & 'C:\ProgramData\SentinelLocal\DefenderHardening.ps1' -Profile AuditFirst -WhatIf

既存インストールから更新（旧パッケージv2.4を含む）:

  .\Upgrade-SentinelLocal.ps1

診断:

  C:\ProgramData\SentinelLocal\SelfTest-SentinelLocal.ps1
  C:\ProgramData\SentinelLocal\Check-SentinelLocal.ps1
  C:\ProgramData\SentinelLocal\Verify-SentinelLogs.ps1

Defender
--------
SentinelLocalはDefenderのCloud Protection / Network Protection / PUA / ASR / CFAなどを補助します。
AuditFirstから開始し、業務影響を確認してからBlockへ進める設計です。

SentinelLocal自身でマルウェア最終判定を行うのではなく、
疑わしい対象をDefender Custom Scanへ渡し、Defender判定を優先します。

Firewall
--------
AutoFirewallBlockOnDefenderConfirmationは既定OFFです。
ONの場合もGroup=SentinelLocalの一時ルールとして作り、期限後に削除します。

確認:
  C:\ProgramData\SentinelLocal\Clear-SentinelFirewallRules.ps1 -ListOnly

解除:
  C:\ProgramData\SentinelLocal\Clear-SentinelFirewallRules.ps1

アンインストール
----------------
  .\Uninstall-SentinelLocal.ps1

データも削除:
  .\Uninstall-SentinelLocal.ps1 -RemoveData
