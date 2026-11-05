# 腾讯游戏发行公司level infinity被黑客攻击植入木马，影响范围巨大！

> 官方修复不完整。截至2026-11-0402:01-02:07 UTC 复核，na-webassets[.]playerinfinite[.]com 上的FeedList.feb647c9.js仍返回5,808字节受污染版本;aegis-fix.min.js与images.7fec4c32.js 已修复。

# 重点报告

- 官方 CDN 供应链污染：至少三个官方游戏启动器被植入恶意代码加载器。
- 完整 RAT：LuaJIT 已经暴露出至少19条恶意命令，包括代码命令执行，交互式Shell，文件传输，截屏，凭证采集和加载器Lifetime Management。如果你启动过腾讯的游戏，那么大概率已经出事了。
- 采集重点是各位开发者和AIChain：采集包含各种AI Agent编程工具、SSH GPG Key和多个钱包扩展。

# 执行流程

## Step1：内存木马

将本体插入启动器中，在内存中驻留；首次启动大约 10 ~ 15秒内 集中采集 `.ssh` 密钥、服务器 `.pem` 密钥、CLI、AI Agent `.json` 配置。

## Step2：全面窃取隐私

对 **部分目标** 下发指令，会释放 **恶意DLL劫持浏览器窃取 Cookies**。该行为会写入 `CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` 注册表。

# 影响范围

## 角色

- 开发者们
- 游戏玩家们

## 游戏

- PUBG：绝地求生
- Conan Chop Chop：柯南快快
- Davy x Jones：戴维·琼斯
- Den of Wolves：狼穴
- Dune: Awakening：沙丘：觉醒
- Dune: Spice Wars：沙丘：香料战争
- Exoborne：暂无官方中文名称
- Exterminauts：异克斯小队
- Goddess of Victory: NIKKE：胜利女神：妮姬
- GTFO：暂无官方中文名称（玩家常称之为GTFO）
- Metal: Hellsinger：重金属：地狱歌手
- Nightingale：暂无官方中文名称
- Song of Nunu: A League of Legends Story：努努之歌：英雄联盟外传
- Undawn：黎明觉醒
- V Rising：夜族崛起
- Warhammer 40,000: Darktide：战锤40K：暗潮
- Warhammer: Vermintide 2：战锤：末世鼠疫2

## 软件

- Claude Code
- Gemini
- Cursor
- CodeX
等 AI Agent开发工具

- Chrome
- Opera
- Microsoft Edge
- FireFox
等浏览器均遭到注入

---

# 修复方式

可以用我和AI写的工具自查

[腾讯被投毒入侵检查工具.zip](https://blog.cqjszx.cn/usr/uploads/2026/11/4010887053.zip)

---

参考链接：

- https://zlb.ink/t/topic/52976
- https://zlb.ink/t/topic/52976
- https://www.gamemeca.com/zh/view.php?gid=1782921
- https://zhuanlan.zhihu.com/p/2101365537599140710
- https://github.com/Sheisback/nikke_malware_scanner
