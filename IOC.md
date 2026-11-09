# XWorm 分析包 · IOC 与检测规则

> 分析日期：2026-11-10
> 性质：静态分析（未执行样本）

---

## 一、C2 情报

```
域名    remremrem2021marzo2021[.]duckdns[.]org
IP      109[.]120[.]139[.]126
端口    3009/TCP
归属    荷兰 阿姆斯特丹 / AS210644 AEZA GROUP LLC（防弹主机）
状态    探测时开放
分组    GTA15
```

## 二、通信特征

```
POST / HTTP/1.1
Host: <C2>
Content-Type: application/x-www-form-urlencoded
User-Agent（固定三种之一）：
  Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ... Chrome/60.0.3112.11
  Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) ...
```

**流量里出现 `<Xwormmm>` 字符串即可判定为 XWorm。**

---

## 三、文件哈希

### 最终载荷（XWorm RAT）

```
SHA256  0eec59785a5e8816287839806c195a89c50f93a852eb7b3db563d6245478f7c3
MD5     b72b01d2ae9e0b9b52b9bf60baf17e6c
大小    33,280 字节
类型    VB.NET / .NET Framework 4.0
```

### ScreenConnect 投递器（被滥用的合法 RMM）

```
8ba658bc2e047721c23780037d2a70c6340727e1c25069e474b700b4a864ae79   kappa.exe
2ec27605d8a42fea6ef86e6f8b7fd416c2ef598f5e912333c5c4c0ec14a47314   Howard.ScreenConnect.ClientSetup.msi
47f3c8d52a9d6842eb1d5fd2ea893be9d127a9c35a5bcd5398d47fde6ebff0c4   zzfa.ScreenConnect.ClientSetup.msi
```

### 同波活动（微软博客披露，样本库未收录）

```
16562974deec80e41ef57a71a6de8c03ceb393005fb1432f8d9d82c61294ef8c
1b2555b09ac62164638f47c8272beb6b0f97186e37d3a54cb84c723ff7a2eee5
062bb28765fbaa11f8cc341fa16e2c7f942a122d929cb41f4a0f755b4429f246
c7425fbe6c3a4937934215c54027d4b67202d12ab490682fae03498870d66d06
```

---

## 四、主机行为特征

### 进程名

```
矿工类    SRBMiner-MULTI.exe / lolMiner.exe / gminer.exe / miner.exe
收割类    CookieHarvester / DiscordHarvester / CursorHarvester / ClaudeHarvester
投递类    SimpleRunPE.exe / ccv.exe / mzcv.exe
伪装名    SecurityHealthHost.exe / RuntimeHost.exe / GameBox.exe
          （合法进程名，需检查路径是否在 System32 外）
远控类    ScreenConnect.ClientService.exe
```

### 系统改动

```
Defender 排除项被批量添加（案例中 88 条）
\drivers\etc\hosts 被修改
注册表 Software\ 下异常启动项
```

### 挖矿运行时特征

```
矿池端口  4041（PRL 币）
日志标记  MINER_START
Linux 侧  /tmp/.boat_inst.sh、/tmp/.boat_rescue.sh、/tmp/.boat.lock
伪装进程  /usr/sbin/sshd、PlexScriptHost
```

---

## 五、XWorm 指令集（用于判断是否被控制）

```
RunShell              远程执行命令
StartDDos / StopDDos  DDoS 攻击
OfflineKeylogger      离线键盘记录
UACFunc               UAC 提权
plugin / sendPlugin   插件系统
PCShutdown/Restart    关机/重启
Xchat                 远程聊天
Hosts                 改 hosts 文件
URLopen/Urlhide       打开/隐藏网页
USB.exe               U 盘传播
update                自我升级
```

---

## 六、封禁配置

### Windows 防火墙

```powershell
New-NetFirewallRule -DisplayName "Block XWorm C2" -Direction Outbound `
  -RemoteAddress 109.120.139.126 -Action Block -Profile Any
```

### Linux iptables

```bash
iptables -A OUTPUT -d 109.120.139.126 -j DROP
```

### DNS 黑洞

```
0.0.0.0 remremrem2021marzo2021.duckdns.org
```

---

## 七、自查

```bash
# Windows
python check_miner_virus.py

# 手工速查
powershell -c "Get-CimInstance Win32_Process | ? {$_.Name -match 'SRBMiner|lolMiner|gminer|ccv|mzcv|Harvester'} | select Name,ProcessId,ExecutablePath"
powershell -c "Get-Service | ? {$_.Name -like '*ScreenConnect*'}"
powershell -c "(Get-MpPreference).ExclusionProcess"
```

---

## 八、钓鱼手法

```
投毒渠道  SEO 投毒（Bing 搜索首位出现仿冒官网）
仿冒对象  Hibit Uninstaller / 驱动总裁 / 图吧工具箱
诱饵特征  下载包里的真软件能用，但捆了恶意组件
识别点    ICO 图标不一致；部分钓鱼站用网盘二维码分发
```

---

**免责**：所有分析为静态分析，样本未在任何环境执行。
