# Windows 异常文件夹 / Steam / 程序调用路径 只读排查报告

- 生成时间：2026-11-05T23:14:19+08:00
- 主机：DESKTOP-OVUQEKD / 用户：Administrator
- 管理员权限：是
- 扫描配置：quick；耗时 41.3 秒
- 工具版本：1.0.0

## 结论摘要

**总体级别：中** — 发现需要人工核对的异常

优先核对高/中优先级条目的文件签名、修改时间与来源；不要直接删除系统目录。

发现计数：严重 0，高 0，中 2，低 2，信息 1。

优先核对：

- **[中]** 可疑程序调用路径：Animate.exe — D:\An2024\Adobe Animate 2024\Animate.exe
- **[中]** 可疑程序调用路径：Photoshop.exe — D:\Photoshop2024\Adobe Photoshop 2024\Photoshop.exe
- **[低]** PATH 中 System32 之前存在用户可写目录 — C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps
- **[低]** PATH 包含空项、相对路径或当前目录
- **[信息]** hosts 文件包含 Steam 域名映射 — C:\Windows\System32\drivers\etc\hosts

## 先看这几条限制

- 本工具是**只读分诊**，不删除、不隔离、不改注册表；它不能证明系统“干净”。
- 公开的 NIKKE/K2F 报告**没有**把“C: 根目录乱码文件夹”或“Steam 安装路径被改写”列为 IOC。本报告中的相关命中是独立线索，不等于 K2F。
- Authenticode 有效只说明文件由该签名者签署且未被改动，不能证明它是最新版本；Steam 更新会正常改变哈希。
- 首次运行没有基线；第二次运行才能对比 Steam 路径/核心文件哈希的波动。

## 全部发现（按级别）

| 级别 | 类别 | 发现 | 路径 | 说明 |
|---|---|---|---|---|
| 中 | Execution | 可疑程序调用路径：Animate.exe | D:\An2024\Adobe Animate 2024\Animate.exe | 签名校验失败：HashMismatch |
| 中 | Execution | 可疑程序调用路径：Photoshop.exe | D:\Photoshop2024\Adobe Photoshop 2024\Photoshop.exe | 签名校验失败：HashMismatch |
| 低 | Execution | PATH 中 System32 之前存在用户可写目录 | C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps | 不一定是恶意，但会扩大命令劫持面。 |
| 低 | Execution | PATH 包含空项、相对路径或当前目录 |  | Windows 会按 PATH 顺序查找程序；空项/当前目录可导致当前目录中的同名程序被执行。 |
| 信息 | Steam integrity | hosts 文件包含 Steam 域名映射 | C:\Windows\System32\drivers\etc\hosts | hosts 中存在指向回环/黑洞地址的 Steam 域名映射，通常是 Steam++/Watt Toolkit 等工具或广告屏蔽；这是信息项，不是恶意判定。 |

## 1. C: 盘乱码/异常文件夹

扫描目录 34780 个，候选 196 个，耗时 11.34 秒。
候选级别：高 0 / 中 0 / 低 196 / 信息 0。这里的高/中才进入“发现”；低优先级多为安装器/缓存/开发工具。
完整目录清单：D:\Downloads\VirusChecker\reports\final\scanned_dirs.jsonl（34797 条 JSONL；GUI 的“目录（全部）”可完整分页查看）。


| 级别 | 分数 | 路径 | 原因 | 修改时间 |
|---|---|---|---|---|
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\cq-pdf-284f68d97ddc | random-looking name (entropy 3.41, vowel ratio 0.00)；long mixed letter/digit token；inside a user-writable location | 2026-10-20T16:26:39+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\cq-pdf-9373d78fd510 | random-looking name (entropy 3.58, vowel ratio 0.00)；long mixed letter/digit token；inside a user-writable location | 2026-10-20T16:26:39+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\cq-pdf-c4acb9102d6b | random-looking name (entropy 3.68, vowel ratio 0.09)；long mixed letter/digit token；inside a user-writable location | 2026-10-20T16:26:39+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\wem-dcl-1791269169883 | random-looking name (entropy 3.65, vowel ratio 0.17)；long mixed letter/digit token；inside a user-writable location | 2026-10-20T16:26:39+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-umxz10hb | random-looking name (entropy 3.68, vowel ratio 0.19)；long mixed letter/digit token；inside a user-writable location | 2026-10-27T15:25:27+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-jj8qk_l3 | random-looking name (entropy 3.55, vowel ratio 0.13)；long mixed letter/digit token；inside a user-writable location | 2026-10-27T15:32:23+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-q84al8_r | random-looking name (entropy 3.55, vowel ratio 0.21)；long mixed letter/digit token；inside a user-writable location | 2026-10-27T15:34:01+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-2ex2pxk8 | random-looking name (entropy 3.48, vowel ratio 0.20)；long mixed letter/digit token；inside a user-writable location | 2026-10-27T15:48:44+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-s1gvij3c | random-looking name (entropy 3.65, vowel ratio 0.19)；long mixed letter/digit token；inside a user-writable location | 2026-10-27T15:50:42+00:00 |
| 低 | 3.1 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-1s227awl | random-looking name (entropy 3.55, vowel ratio 0.21)；long mixed letter/digit token；inside a user-writable location | 2026-10-27T15:59:10+00:00 |
| 低 | 2.8 | C:\Users\Administrator\AppData\Roaming\ollama app.exe | directory name looks like an executable/script file；inside a user-writable location | 2026-08-23T00:09:14+00:00 |
| 低 | 2.8 | C:\Users\Administrator\AppData\Local\Temp\Turn10Temp.scratch | random-looking name (entropy 3.84, vowel ratio 0.20)；high name entropy (3.84)；inside a user-writable location | 2026-10-31T06:00:03+00:00 |
| 低 | 2.8 | C:\Users\Administrator\AppData\Local\Temp\node-compile-cache\v24.19.0-x64-cf738c9d | random-looking name (entropy 3.92, vowel ratio 0.00)；high name entropy (3.92)；inside a user-writable location | 2026-11-04T16:24:19+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\RailCrashReport\UnsentCrashReports\TinyDL_1.6.24.0 | random-looking name (entropy 3.59, vowel ratio 0.17)；inside a user-writable location | 2026-08-22T02:50:33+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\assembly\dl3\RHJYPW1C.8PA | random-looking name (entropy 3.42, vowel ratio 0.11)；inside a user-writable location | 2026-08-22T13:53:17+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\ms-playwright | random-looking name (entropy 3.70, vowel ratio 0.17)；inside a user-writable location | 2026-08-28T01:38:26+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\nsjB9F8.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-08-29T01:33:15+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\nsx73E2.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-08-29T01:33:15+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9A48.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-09-23T16:55:06+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9BE2.tmp | random-looking name (entropy 3.46, vowel ratio 0.12)；inside a user-writable location | 2026-09-23T16:55:07+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9E0B.tmp | random-looking name (entropy 3.46, vowel ratio 0.12)；inside a user-writable location | 2026-09-23T16:55:07+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9EB1.tmp | random-looking name (entropy 3.46, vowel ratio 0.12)；inside a user-writable location | 2026-09-23T16:55:07+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9F40.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-09-23T16:55:08+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9F81.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-09-23T16:55:08+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9FA2.tmp | random-looking name (entropy 3.46, vowel ratio 0.12)；inside a user-writable location | 2026-09-23T16:55:08+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD9FB4.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-09-23T16:55:08+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\burp3704441235996997074.tmp | random-looking name (entropy 3.76, vowel ratio 0.14)；inside a user-writable location | 2026-10-02T05:49:24+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-tour-1791268633304\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T06:38:30+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-job-a-1791270112052\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T07:02:33+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-t-1791270541753\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T07:09:49+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-t-1791270619915\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T07:11:04+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-t-1791270680094\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T07:12:04+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-probe-1791270898035\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T07:15:45+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-one-1791271098900\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T07:19:00+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wf-1791273208562\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T07:54:15+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\wem-tour-1791273646305\Default\Extensions\pdffkfellgipmhklpdmokmckkkfcopbh | random-looking name (entropy 3.47, vowel ratio 0.12)；inside a user-writable location | 2026-10-06T08:01:29+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD751E.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-10-18T08:37:43+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD753F.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-18T08:37:43+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD7564.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-18T08:37:43+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD758A.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-10-18T08:37:43+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD75AB.tmp | random-looking name (entropy 3.46, vowel ratio 0.12)；inside a user-writable location | 2026-10-18T08:37:43+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD75EF.tmp | random-looking name (entropy 3.46, vowel ratio 0.12)；inside a user-writable location | 2026-10-18T08:37:43+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD7601.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-18T08:37:43+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD47E2.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-10-22T14:26:21+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD47E3.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-10-22T14:26:21+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD47F6.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-22T14:26:21+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD4829.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-22T14:26:21+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD486B.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-22T14:26:21+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD4A08.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-10-22T14:26:21+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\TCD4A96.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-10-22T14:26:22+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\nsa1C93.tmp | random-looking name (entropy 3.46, vowel ratio 0.14)；inside a user-writable location | 2026-10-26T15:13:47+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\nsj1B85.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-26T15:25:56+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\nsf7FC8.tmp | random-looking name (entropy 3.46, vowel ratio 0.00)；inside a user-writable location | 2026-10-26T15:27:27+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-grphiqlk | random-looking name (entropy 3.65, vowel ratio 0.17)；inside a user-writable location | 2026-10-27T15:25:21+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\qqbot-tests-tgmxzuvn | random-looking name (entropy 3.62, vowel ratio 0.17)；inside a user-writable location | 2026-10-27T15:56:17+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546735417\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:25:36+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546746959\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:25:48+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546760310\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:26:01+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546735417\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:26:01+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546746959\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:26:13+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546779264\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:26:20+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546760310\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:26:27+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546779264\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:26:45+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546853541\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:27:34+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546859922\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:27:41+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546866303\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:27:47+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546853541\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:28:00+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546859922\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:28:06+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793546866303\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:28:12+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547094568\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:31:35+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547101019\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:31:41+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547107490\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:31:48+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547094568\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:32:01+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547101019\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:32:07+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547107490\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:32:14+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547194234\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:33:15+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-probe-1793547219952\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:33:40+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-edge-1793547194234\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:33:41+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-probe-1793547238008\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold | random-looking name (entropy 3.57, vowel ratio 0.22)；inside a user-writable location | 2026-11-01T15:34:00+00:00 |
| 低 | 2.3 | C:\Users\Administrator\AppData\Local\Temp\dsh-probe-1793547219952\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha | random-looking name (entropy 3.63, vowel ratio 0.19)；inside a user-writable location | 2026-11-01T15:34:07+00:00 |

## 2. Steam 路径与范围波动

主安装目录：d:\steam

### 安装根

| 主 | 路径 | steam.exe | 来源 | 盘类型 | 链接 |
|---|---|---|---|---|---|
| 是 | d:\steam | d:\steam\steam.exe | registry:HKCU\Software\Valve\Steam:SteamExe | fixed |  |

### 库目录

| 路径 | 存在 | 盘类型 | App 数 | 来源 |
|---|---|---|---|---|
| D:\Steam | 是 | fixed | 7 | d:\steam\steamapps\libraryfolders.vdf |
| E:\SteamLibrary | 是 | fixed | 9 | d:\steam\steamapps\libraryfolders.vdf |

### 与基线的范围波动

与基线一致，未发现 Steam 路径/核心哈希变化。

## 3. Steam 客户端完整性

结论：**签名/结构未发现异常**；客户端版本：11.15.70.27

| 文件 | 签名状态 | Valve | 签名者 | SHA-256 | 问题 |
|---|---|---|---|---|---|
| steam.exe | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | f8a4ca44008c516e... |  |
| steamclient.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | a9b8b99058898887... |  |
| steamclient64.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | 253e0a11a4415b38... |  |
| steamui.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | cd9226db4e6c2894... |  |
| gameoverlayrenderer.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | 1afe9b93e0f36cbe... |  |
| gameoverlayrenderer64.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | 05a62859e55a9f2a... |  |
| tier0_s.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | affcd9b94f5155b0... |  |
| tier0_s64.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | 8559e6bd32eb3fdd... |  |
| vstdlib_s.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | 8495e7c62a4ef461... |  |
| vstdlib_s64.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | f63f348bb18460b3... |  |
| crashhandler.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | ef9edb675ddd1f11... |  |
| crashhandler64.dll | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | 71dac2711f6c2301... |  |
| bin\steamservice.exe | Valid | 是 | CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US | 219fc62d4ac64cdd... |  |

### 完整性发现

| 级别 | 类别 | 发现 | 路径 | 说明 |
|---|---|---|---|---|
| 信息 | Steam integrity | hosts 文件包含 Steam 域名映射 | C:\Windows\System32\drivers\etc\hosts | hosts 中存在指向回环/黑洞地址的 Steam 域名映射，通常是 Steam++/Watt Toolkit 等工具或广告屏蔽；这是信息项，不是恶意判定。 |

## 4. 程序调用路径与可疑软件

进程 260，服务 295，驱动 399，计划任务 245，注册表启动项 111，唯一程序路径 646，可疑 4。

### 可疑调用路径

| 级别 | 分数 | 类型 | 名称 | 路径 | 原因 |
|---|---|---|---|---|---|
| 中 | 8.0 | autoruns | Animate.exe | D:\An2024\Adobe Animate 2024\Animate.exe | 签名校验失败：HashMismatch |
| 中 | 8.0 | autoruns | Photoshop.exe | D:\Photoshop2024\Adobe Photoshop 2024\Photoshop.exe | 签名校验失败：HashMismatch |
| 中 | 8.0 | autoruns | Animate.exe | D:\An2024\Adobe Animate 2024\Animate.exe | 签名校验失败：HashMismatch |
| 中 | 8.0 | autoruns | Photoshop.exe | D:\Photoshop2024\Adobe Photoshop 2024\Photoshop.exe | 签名校验失败：HashMismatch |

### 程序路径清点（按风险排序，前 80）

| 级别 | 分数 | 路径 | 来源 |
|---|---|---|---|
| 中 | 8.0 | D:\An2024\Adobe Animate 2024\Animate.exe | autorun:AppPaths |
| 中 | 8.0 | D:\Photoshop2024\Adobe Photoshop 2024\Photoshop.exe | autorun:AppPaths |
| 低 | 6.0 | C:\Users\Administrator\.dsh\profiles\desktop\node_modules\@dsh-ops\bash-win32-x64\usr\bin\bash.exe | process |
| 低 | 6.0 | C:\Users\Administrator\.dsh\profiles\desktop\node_modules\@dsh-ops\bash-win32-x64\usr\bin\tail.exe | process |
| 低 | 5.0 | D:\Downloads\VirusChecker\Steam++.exe | task:\Steam++_{S-1-5-21-640925113-3983486717-928163845-500} |
| 低 | 4.0 | C:\Program Files (x86)\Neat Download Manager\NeatDM.exe | process；autorun:Run |
| 低 | 4.0 | C:\Program Files\7-Zip\7zFM.exe | autorun:AppPaths |
| 低 | 4.0 | C:\Program Files\AntiCheatExpert\SGuard\x64\plugins\ACE-SSC-DRV64.sys | driver |
| 低 | 4.0 | C:\Program Files\Mem Reduct\memreduct.exe | process；autorun:Run |
| 低 | 4.0 | C:\Program Files\WindowsApps\Microsoft.GetHelp_10.2409.41132.0_x64__8wekyb3d8bbwe\GetHelp.exe | autorun:AppPaths |
| 低 | 4.0 | C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2607.0.0_x64__8wekyb3d8bbwe\CalculatorApp.exe | process |
| 低 | 4.0 | C:\Program Files\WindowsApps\Microsoft.WindowsStore_22609.1401.8.0_x64__8wekyb3d8bbwe\store.exe | autorun:AppPaths |
| 低 | 4.0 | C:\Windows\system32\drivers\BthA2dp.sys | driver |
| 低 | 4.0 | C:\Windows\system32\drivers\bthhfenum.sys | driver |
| 低 | 4.0 | C:\Windows\system32\drivers\bthmodem.sys | driver |
| 低 | 4.0 | D:\FlClash\FlClashHelperService.exe | service |
| 低 | 4.0 | D:\TieZ\tiez-app.exe | process；autorun:Run |
| 低 | 4.0 | D:\钛度-THS326甲胄\UI\Taidu Gaming Headset.exe | process；autorun:Run |
| 低 | 3.0 | C:\Program Files (x86)\Razer\Razer Axon\RazerAxon.exe | task:\AxonLaunchTask；com:{2db59e37-0d0f-9458-c133-85e699bb3bdd} |
| 低 | 3.0 | C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe" -s NvContainerLocalSystem -a -f "C:\ProgramData\NVIDIA\NvContainerLocalSystem.log" -l 3 -d "C:\Program Files\NVIDIA Corporation\NvContainer\plugins\LocalSystem" -r -p 30000 -st "C:\Program Files\NVIDIA Corporation\NvContainer\NvContainerTelemetryApi.dll | service |
| 低 | 3.0 | C:\ProgramData\Microsoft\Windows\Start | startup:desktop.ini |
| 低 | 3.0 | C:\ProgramData\Seewo\Easiupdate3\Easiupdate3\EasiUpdate3.exe | process；service |
| 低 | 3.0 | C:\ProgramData\Seewo\Easiupdate3\Easiupdate3\EasiUpdate3Protect.exe | process；service |
| 低 | 3.0 | C:\ProgramData\Seewo\Easiupdate\easiupdate\EasiUpdate.exe | process；service |
| 低 | 3.0 | C:\Users\Administrator\.dsh\profiles\desktop\node_modules\@dsh-ops\bash-win32-x64\bin\bash.exe | process |
| 低 | 3.0 | C:\Users\Administrator\AppData\Local\JetBrains\Toolbox\bin\jetbrains-toolbox.exe | autorun:Run |
| 低 | 3.0 | C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start | startup:desktop.ini |
| 低 | 3.0 | C:\Users\Administrator\AppData\Roaming\Tencent\xwechat\xplugin\plugins\RadiumWMPF\25819\extracted\runtime\WeChatAppEx.exe | process |
| 低 | 3.0 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | process；autorun:AppPaths |
| 信息 | 2.0 | C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe | task:\Microsoft\VisualStudio\Updates\BackgroundDownload |
| 信息 | 2.0 | C:\Program Files\AntiCheatExpert\ACE-BOOT.sys | driver |
| 信息 | 2.0 | C:\Program Files\AntiCheatExpert\ACE-CORE102706.sys | driver |
| 信息 | 2.0 | C:\Program Files\AntiCheatExpert\ACE-CORE202706.sys | driver |
| 信息 | 2.0 | C:\Program Files\Microsoft OfficePLUS\4.1.0.3274\addin\MSOfficePLUSService.exe | service |
| 信息 | 2.0 | C:\Program Files\NVIDIA Corporation\FrameViewSDK\nvfvsdksvc_x64.exe | service |
| 信息 | 2.0 | C:\Program Files\RUXIM\PLUGscheduler.exe | task:\Microsoft\Windows\WindowsUpdate\RUXIM\PLUGScheduler |
| 信息 | 2.0 | C:\Program Files\Windows Media Player\wmpnscfg.exe | task:\Microsoft\Windows\Windows Media Sharing\UpdateLibrary |
| 信息 | 2.0 | C:\Program Files\WindowsApps\Microsoft.MicrosoftPCManager_3.23.0.0_x64__8wekyb3d8bbwe\PCManager\MSPCManagerService.exe | service |
| 信息 | 2.0 | C:\Windows\system32\bcdboot.exe | task:\Microsoft\Windows\Chkdsk\SyspartRepair |
| 信息 | 2.0 | C:\Windows\system32\ClipRenew.exe | task:\Microsoft\Windows\Subscription\EnableLicenseAcquisition；task:\Microsoft\Windows\Subscription\LicenseAcquisition |
| 信息 | 2.0 | C:\Windows\system32\ClipUp.exe | task:\Microsoft\Windows\Clip\License Validation |
| 信息 | 2.0 | C:\Windows\system32\DFDWiz.exe | task:\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver |
| 信息 | 2.0 | C:\Windows\system32\directxdatabaseupdater.exe | task:\Microsoft\Windows\DirectX\DirectXDatabaseUpdater |
| 信息 | 2.0 | C:\Windows\system32\drivers\applockerfltr.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\EhStorTcgDrv.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\gvinputmf.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\DRIVERS\hrdevmon.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\i8042prt.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\IndirectKmd.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\DRIVERS\ipfltdrv.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\MTConfig.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\WdFilter.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\WindowsTrustedRT.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\drivers\WindowsTrustedRTProxy.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\DriverStore\FileRepository\nvppc.inf_amd64_0fb3e9fb3fdb0d20\UcmCxUcsiNvppc.sys | driver |
| 信息 | 2.0 | C:\Windows\system32\dxgiadaptercache.exe | task:\Microsoft\Windows\DirectX\DXGIAdapterCache |
| 信息 | 2.0 | C:\Windows\system32\fclip.exe | task:\Microsoft\Windows\Clip\LicenseImdsIntegration |
| 信息 | 2.0 | C:\Windows\system32\ProvTool.exe | task:\Microsoft\Windows\Management\Provisioning\Cellular；task:\Microsoft\Windows\Management\Provisioning\Logon；task:\Microsoft\Windows\Management\Provisioning\Retry；task:\Microsoft\Windows\Management\Provisioning\RunOnReboot |
| 信息 | 2.0 | C:\Windows\system32\RAServer.exe | task:\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask |
| 信息 | 2.0 | C:\Windows\system32\rundll32.exe | process；task:\Microsoft\Windows\Application Experience\PcaPatchDbTask；task:\Microsoft\Windows\Application Experience\PcaWallpaperAppDetect；task:\Microsoft\Windows\Application Experience\StartupAppTask |
| 信息 | 2.0 | C:\Windows\system32\UCPDMgr.exe | task:\Microsoft\Windows\AppxDeploymentClient\UCPD velocity |
| 信息 | 2.0 | C:\Windows\System32\WiFiTask.exe | task:\Microsoft\Windows\NlaSvc\WiFiTask；task:\Microsoft\Windows\WCM\WiFiTask；task:\Microsoft\Windows\WwanSvc\NotificationTask |
| 信息 | 2.0 | C:\Windows\System32\WinBioPlugIns\FaceFodUninstaller.exe | task:\Microsoft\Windows\HelloFace\FODCleanupTask |
| 信息 | 2.0 | D:\BaiduNetdisk\YunUtilityService.exe | service |
| 信息 | 1.0 | C:\Program | protocol:http；protocol:https |
| 信息 | 1.0 | C:\Program Files (x86)\Adobe\Adobe Creative Cloud Experience\CCXProcess.exe | autorun:Run |
| 信息 | 1.0 | C:\Program Files (x86)\Common Files\BattlEye\BEService.exe | service |
| 信息 | 1.0 | C:\Program Files (x86)\Common Files\Java\Java Update\jucheck.exe | process |
| 信息 | 1.0 | C:\Program Files (x86)\Common Files\Java\Java Update\jusched.exe | process；autorun:Run |
| 信息 | 1.0 | C:\Program Files (x86)\Tencent\UpdateSvr\WemeetUpdateSvc.exe | service |
| 信息 | 1.0 | C:\Program Files\AntiCheatExpert\ACE-Service64.exe | service |
| 信息 | 1.0 | C:\Program Files\AntiCheatExpert\ACE-Tray.exe | process；autorun:Run |
| 信息 | 1.0 | C:\Program Files\AntiCheatExpert\SGuard\x64\SGuardSvc64.exe | service |
| 信息 | 1.0 | C:\Program Files\Common Files\PUBG\zksvc.exe | service |
| 信息 | 1.0 | C:\Program Files\LGHUB\lghub_agent.exe | process |
| 信息 | 1.0 | C:\Program Files\LGHUB\lghub_updater.exe | process；service |
| 信息 | 1.0 | C:\Program Files\LGHUB\system_tray\lghub_system_tray.exe | process；autorun:Run |
| 信息 | 1.0 | C:\Program Files\Tencent\WeType\3.0.1.28\wetype_renderer.exe | process |
| 信息 | 1.0 | C:\Program Files\Tencent\WeType\3.0.1.28\wetype_server.exe | process |
| 信息 | 1.0 | C:\Program Files\Tencent\WeType\3.0.1.28\wetype_service.exe | process；service |

### PATH 分析

| 范围 | 序号 | 原始项 | 类型 | 存在 | 用户可写 |
|---|---|---|---|---|---|
| machine | 0 | C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin | directory | 是 | 否 |
| machine | 1 | C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\libnvvp | directory | 是 | 否 |
| machine | 2 |  | empty | 否 | 否 |
| machine | 3 |  | empty | 否 | 否 |
| machine | 4 | %SystemRoot%\system32 | directory | 是 | 否 |
| machine | 5 | %SystemRoot% | directory | 是 | 否 |
| machine | 6 | %SystemRoot%\System32\Wbem | directory | 是 | 否 |
| machine | 7 | %SYSTEMROOT%\System32\WindowsPowerShell\v1.0\ | directory | 是 | 否 |
| machine | 8 | %SYSTEMROOT%\System32\OpenSSH\ | directory | 是 | 否 |
| machine | 9 | D:\Program Files (x86)\IncrediBuild | directory | 是 | 否 |
| machine | 10 | D:\Windows Kits\10\Windows Performance Toolkit\ | directory | 是 | 否 |
| machine | 11 | D:\nodejs\ | directory | 是 | 否 |
| machine | 12 | C:\Program Files (x86)\NVIDIA Corporation\PhysX\Common | directory | 是 | 否 |
| machine | 13 | D:\GoDev\bin | directory | 是 | 否 |
| machine | 14 | D:\Git\cmd | directory | 是 | 否 |
| machine | 15 | C:\ProgramData\ComposerSetup\bin | directory | 是 | 是 |
| machine | 16 | C:\Program Files\NVIDIA Corporation\NVIDIA NvDLISR | directory | 是 | 否 |
| machine | 17 | C:\Program Files\NVIDIA Corporation\Nsight Compute 2020.3.0\ | directory | 是 | 否 |
| user | 0 | D:\dsh\resources\runtime\cli\bin | directory | 是 | 否 |
| user | 1 | D:\python312_64\Scripts\ | directory | 是 | 否 |
| user | 2 | D:\python312_64\ | directory | 是 | 否 |
| user | 3 | C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps | directory | 是 | 是 |
| user | 4 | C:\Users\Administrator\AppData\Local\JetBrains\Toolbox\scripts | directory | 是 | 是 |
| user | 5 | C:\Users\Administrator\AppData\Roaming\npm | directory | 是 | 是 |
| user | 6 | %USERPROFILE%\go\bin | missing | 否 | 否 |
| user | 7 | C:\Users\Administrator\AppData\Local\GitHubDesktop\bin | directory | 是 | 是 |
| user | 8 | D:\php-8.4.24-Win32-vs17-x64 | directory | 是 | 否 |
| user | 9 | C:\Users\Administrator\AppData\Roaming\Composer\vendor\bin | missing | 否 | 是 |
| user | 10 | D:\Ollama | directory | 是 | 否 |
| user | 11 | D:\ffmpeg\bin | directory | 是 | 否 |
| user | 12 | D:\uv-aarch64-pc-windows-msvc\ | directory | 是 | 否 |
| user | 13 | D:\dex-tools-v2.4 | directory | 是 | 否 |
| user | 14 | D:\Desktop\APKs | missing | 否 | 是 |
| user | 15 | D:\java8\bin | directory | 是 | 否 |
| user | 16 | D:\mysql-5.7.44-winx64\bin\ | directory | 是 | 否 |
| user | 17 | D:\Android SDK\platform-tools | directory | 是 | 否 |
| user | 18 |  | empty | 否 | 否 |

## 5. NIKKE / K2F 专项

结论：**未发现公开 K2F 指标**；第 0 阶段：未发现公开 IOC；阶段 1/2/3/4：False/False/False/False

_无_

### 发现的 NIKKE 候选目录

_无_

## 6. 扫描统计与错误

| 项目 | 数值 |
|---|---|
| 异常文件夹候选 | 196 |
| 目录清单记录 | 34797 |
| Steam 安装根 | 1 |
| Steam 库 | 2 |
| Steam 核心文件 | 13 |
| 唯一程序路径 | 646 |
| 可疑程序/启动项 | 4 |
| K2F 发现 | 0 |
| 错误/不可读 | 0 |

## 7. 建议的下一步

1. 先处理 high/critical：不要直接删除，先复制文件、记录哈希/签名/时间。
2. 如果 K2F 专项出现 high/critical：按事件处置断网，从另一台设备改密码、撤销 API key、SSH/GPG，并转移钱包资产。
3. 如果 Steam 核心文件签名异常：备份后让 Steam 校验文件；若同时存在未知 DLL/模块，按被注入处理。
4. 如果只是乱码文件夹：先确认是否来自解压工具/旧软件；不要因为名字奇怪就删除数据。
5. 第二次运行可对比 Steam 基线；确认当前状态正常后再更新基线。

---

参考：WormW/nikke_malware_analysis、WizerdBaChe/nikke-k2f-check、Level Infinite 官方公告与 Gamemeca 报道。公开 IOC 仅用于防御；不要主动连接 C2。