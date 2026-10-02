SentinelLocal v1.2.1（Windows専用）
================================

Microsoft Defenderを防御エンジンとして利用するHost IDS / Defender補助コントローラーです。
独立アンチウイルス、Protected Process、カーネルEDRではありません。
用途はWindows PC 1台の試験運用です。

導入・更新
----------
配布payloadとは独立して信頼したBootstrapと署名者pinを用意し、
管理者Windows PowerShell 5.1で検証・保護stagingから導入します。
Install-SentinelLocal.ps1 / Upgrade-SentinelLocal.ps1をDownloadsから直接実行しません。
通常手順はREADME.md、開発用手順はdocs/PILOT_JP.mdを参照してください。
署名なしはDevelopmentUnsignedと独立にレビューしたExpectedManifestSHA256が必須です。
現在の開発版には製品用の信頼済み署名はありません。

Defender設定は通常導入で変更しません。
変更計画の確認:
  & 'C:\ProgramData\SentinelLocal\DefenderHardening.ps1' -Profile AuditFirst -WhatIf

診断・記録
----------
  & 'C:\ProgramData\SentinelLocal\SelfTest-SentinelLocal.ps1'
  & 'C:\ProgramData\SentinelLocal\Check-SentinelLocal.ps1'
  & 'C:\ProgramData\SentinelLocal\Verify-SentinelLogs.ps1'
logs/に監視・警告、state/にキューとbaseline、evidence/に調査資料を保存します。
LiveTargetMissing / LiveTargetChangedはHIGH未解決です。
failedキューと未解決証拠、queued snapshotは自動期限削除しません。
容量制限に達したら調査・監査出力後に管理者が整理します。

詳しい運用: docs/OPERATIONS_JP.md
PC試験運用: docs/PILOT_JP.md
v1.2.1修正と制限: docs/SECURITY_JP.md
ソース構造・開発: docs/REPOSITORY_JP.md

管理者/SYSTEM・カーネル権限の攻撃者への保護、商用製品相当の検知率は保証しません。
CMSの失効確認・タイムスタンプ・巻き戻し防止は未実装です。
Bootstrap自体の信頼を独立に確認してください。
