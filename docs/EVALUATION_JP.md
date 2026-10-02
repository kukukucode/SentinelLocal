# 防御性能の段階的な評価

SentinelLocalはWindows専用です。実マルウェアの検知率、正常操作の誤検知率、検知時間、ATT&CKカバレッジは現在未測定です。このガイドとtools/evaluation/は、結果の記録・集計基盤を用意する最初の段階です。CIの回帰試験件数は防御性能を表しません。

## 段階と現在の到達点

1. **結果の形式と集計（今回）**：JSONで試験結果を記録し、SentinelLocalとDefenderを個別に集計する。架空データで計算を検証する。
2. **無害な操作による実測（準備診断まで実装）**：測定前に導入・監視プロセス・ログ・Defenderの状態を読み取り専用で確認する。次に通常のアプリ起動・日常操作を記録し、観測の健全性と警告の対応づけを確認する。範囲を限定した無害な技術再現で検知時間も測る。
3. **ATT&CKの試験拡充**：対象バージョンと技術を固定し、技術ごとの再現試験・未検知・誤検知を蓄積する。
4. **実マルウェア検体群の評価**：専用の隔離Windows環境で、出所・分類・SHA-256を管理した検体群を用いて測る。

今回のツールは入力済みの結果の集計と、測定前の準備診断に対応します。試験の実行、ログの自動相関、Defenderスキャン、インストール、設定変更、検体の取得を行う機能は次の段階以降です。通常のPC上で実マルウェアを実行する手順ではありません。

## 実測前の読み取り専用診断

レビューしたソースリポジトリから実行してください。診断はリポジトリ内のコードだけを使用し、導入先のPS1を読み込んで実行しません。Rootは実際の導入先、OutputDirectoryは導入先の外にある新しいフォルダーを指定します。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\evaluation\Test-SentinelEvaluationReadiness.ps1 `
  -Root C:\ProgramData\SentinelLocal `
  -OutputDirectory .\reports\evaluation-readiness

Get-Content .\reports\evaluation-readiness\readiness.json -Raw -Encoding UTF8 | ConvertFrom-Json
```

診断は導入ファイルと設定、3コンポーネントの新しいHeartbeat・プロセス・タスク定義、JSONLログのハッシュチェーンとcheckpoint、Defenderの有効状態・イベントチャネルを確認します。Sysmon連携が有効なら、そのチャネルへのアクセスも確認します。プロセスはPIDだけでなく、PowerShellの実体パス、コンポーネントとRootの引数、Heartbeatより前の生成時刻を確認します。Response WorkerがBusyの場合は、処理が完了してIdleになるまで測定開始を見送ります。

結果はreadiness.jsonです。各項目のPass / Fail / Unverifiedと次に確認する内容を示します。すべてPassならReadyForBenignTrials=trueと終了コード0、未導入・不調・アクセス不可などがあればfalseと終了コード2です。出力先の上書きや導入先への出力指定など、呼び出し自体のエラーは終了コード1です。導入先と報告先のパスがリンクや接合点を経由する場合も拒否します。保護されたファイルやSYSTEMタスクの確認には、管理者PowerShellでの実行が必要な場合があります。アクセス不可を正常と扱いません。

診断は監視プロセス・タスク・Defender・Sysmonの設定を変更せず、ログの未完了トランザクションや古いcheckpointも修復しません。空のログしかない場合は、ログ収集が実証されていないとしてUnverifiedになります。診断結果にはPerformanceMeasured=falseを記録し、試行結果や誤検知率を生成しません。ReadyForBenignTrialsは測定を開始する前提条件の確認であり、試行中の継続的な監視・ログ収集や防御性能の証明ではありません。実測時には開始前と終了後に確認し、観測窓全体のログも別途検証してください。

この診断は既存導入の信頼性を認証するものではありません。導入は独立Bootstrapによる検証手順を使用してください。診断結果にPCのパスやローカル状態が含まれるため、reports/内に保存し、公開リポジトリには登録しません。

## 架空データで集計を試す

ソースリポジトリのルートで、Windows PowerShell 5.1から実行します。管理者権限は不要です。出力先はまだ存在しないフォルダーを指定します。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\evaluation\Export-SentinelEvaluation.ps1 `
  -InputPath .\tools\evaluation\synthetic-example.json `
  -OutputDirectory .\reports\evaluation-example

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-EvaluationTests.ps1
```

出力は、確認用のsummary.md、機械処理用のsummary.json、検証した入力を残すresults.jsonです。実行結果はreports/に保存し、Gitには登録しません。出力先が存在する場合は上書きを拒否します。

synthetic-example.jsonの件数・時刻・ハッシュはすべて架空です。出力にはSYNTHETIC DATAと表示されます。この例から算出された割合や秒数を製品の評価として引用しないでください。

配布パッケージに集計ツールは含めません。集計を行う場合はソースリポジトリを利用します。

## 入力形式：Schema 1

入力はJSONオブジェクトです。フィールド名と列挙値は大文字・小文字を区別します。未知のフィールド、必要なフィールドの欠落、不正な型を拒否します。

| Runの項目 | 意味 |
| --- | --- |
| Id | 試験実行の識別子 |
| EvidenceType | Synthetic（架空）またはMeasured（実測を記録した入力） |
| SentinelVersion / ConfigSHA256 | バージョンと、その試験に実際に使用したConfig.jsonのSHA-256 |
| WindowsVersion / DefenderVersion / SysmonVersion | 試験環境のバージョン。未導入の場合はNotInstalledなど、明示的な文字列 |
| CorpusId | 試験対象一覧を識別できる名前や版。検体・正常操作・再現試験の一覧を別途保管する |
| AttackVersion | 試験計画で固定したATT&CKの版。試験対象がなければNotAssessed |
| AttackScope | 対象技術IDの配列。未試験も含めて事前に固定する。対象なしは空配列 |

Casesは試行結果の配列です。空配列も受け付け、割合と時間を未測定として出力します。

| Caseの項目 | 意味 |
| --- | --- |
| Id | 一意な試行ID |
| Category | Malware、Benign、Emulation |
| Status | Completed（観測が完了）またはError（試験・観測が失敗） |
| StartedAt / EndedAt | 試験対象の操作開始と観測窓の終了時刻。ISO 8601でZまたは時差を必須とする |
| ArtifactSHA256 | Malwareで必須の検体SHA-256。他の分類でもファイルを試す場合は指定可能 |
| TechniqueId | EmulationはAttackScope内の技術IDを1つ指定。MalwareとBenignはnull |
| Alerts | その試行に対応づけた警告の配列。未検知は空配列 |
| Error | StatusがErrorの場合に必須の理由。Completedには指定しない |

Alertsの各要素はSource（SentinelまたはDefender）、Timestamp（時差付き警告時刻）、EvidenceRef（ログの場所・レコードIDなど）を持ちます。時刻は試行の観測窓内である必要があります。EvidenceRefは文字列として保存し、リンク先やファイルを自動取得しません。

Completedを記録する前に、試験が実際に開始されたこと、Watcher等の必要な監視が正常であったこと、予定した観測窓の最後までログを収集できたことを確認します。対象が実行できない、監視が停止した、ログを取得できない等の場合はErrorにします。集計ツール自体は、その実機状態やEvidenceRefの真正性を検証しません。Measuredは入力者による申告であり、第三者評価の認証ではありません。

SentinelLocalがDefenderの検知を取り込んで警告した場合、それぞれの証拠と警告時刻を記録します。このケースのSentinel警告はDefenderの情報を利用したものです。エンジンごとの集計は独立した検知能力を証明せず、詳細な検知経路は証拠と合わせて確認する必要があります。

## 集計方法

| 指標 | この段階での定義 |
| --- | --- |
| 検知率 | Malwareの警告ありCompleted試行数 ÷ MalwareのCompleted試行数 |
| 誤検知率 | Benignの警告ありCompleted試行数 ÷ BenignのCompleted試行数 |
| 検知時間 | StartedAtから各Sourceの最初の警告までの秒数。警告あり試行の中央値・p95・最大値を分類ごとに出す |
| ATT&CK試験範囲内の観測率 | 警告ありのEmulation試行が1件以上ある技術数 ÷ CompletedのEmulation試行が1件以上ある技術数 |

これらをSentinelとDefenderのそれぞれについて計算します。割合は0〜1の数値としてJSONに保存し、Markdownでは百分率で表示します。Error試行は分母から除き、件数を明示します。分母が0ならJSONのnull、MarkdownのN/Aです。

同じ試行内の警告が複数あっても1件として数え、最初の警告時刻を使用します。未検知のCompleted試行は率の分母に含めますが、検知時間の計算には入りません。したがって時間だけを見て高速と判断せず、未検知数と一緒に評価します。p95は昇順の観測値のceil(0.95×件数)番目を取るnearest-rank方式です。

単位は**試行**です。同じ検体の繰り返しも別Idなら別試行となり、唯一の検体数を表しません。実検体の試験ではSHA-256による重複管理、ファミリー別の構成、採取時期、ラベルの根拠、観測窓、繰り返し回数を計画書で固定してください。正常操作も選び方で誤検知率が変わります。小さな試験群の割合を、Windows全体や未知のマルウェアへ一般化できません。

Emulationの警告率を実マルウェア検知率に混ぜません。EICARも実マルウェア検体群の代わりにはなりません。[EICAR公式説明](https://www.eicar.org/download-anti-malware-testfile/)では、実ウイルスを使用せずアンチウイルスの応答を確認するためのファイルとされています。

ATT&CKは技術ごとにNotTested、TestedNoDetection、DetectedInSomeTrials、DetectedInAllTrialsを出します。Errorしかない技術はNotTestedです。単一技術を対象にした試行で警告の根拠がその技術に対応するか確認してから記録してください。試行内の無関係な警告やログ取得だけを検知として数えません。試験した技術の一部実装についての結果であり、その技術のすべての変種やATT&CK全体への対応を保証しません。警告は阻止・駆除を意味せず、阻止率はこの段階では集計しません。[MITREの評価・開発ガイド](https://attack.mitre.org/resources/get-started/assessment-and-engineering/)も参照してください。

## 次に実測する項目

まず、正常なアプリ起動や通常のPowerShell操作を限定した一覧で試し、観測開始・終了と警告の証拠を自動記録する補助ツールを追加します。そこで正常に観測できることを確かめてから、無害な技術再現、対象技術の拡大、隔離環境での実検体評価へ進みます。
