# XWorm 分析包（2026-11-10）

一句话：从一个 42KB 的 PowerShell 脚本里，扒出了一个 33KB 的远程控制木马，还找到了它的 C2 服务器。

---

## 包内容

| 文件 | 说明 |
|---|---|
| `IOC清单.md` | C2、哈希、行为特征、封禁配置、自查命令 |
| `rules_xworm.yar` | XWorm 专用 YARA 规则（4 条，已用真实样本验证命中） |
| `rules_screenconnect.yar` | ScreenConnect 投递链规则（4 条，已验证） |
| `check_miner_virus.py` | 主机自查脚本（Windows，只读检测） |
| `拆解过程.md` | 12 层加密的完整拆解步骤与技术细节 |

---

## 快速用法

### 1. 查自己电脑有没有中招

```bash
python check_miner_virus.py
```

输出 `未发现已知 IOC 命中` 就是干净。

### 2. 用 YARA 扫可疑文件

```bash
yara -w rules_xworm.yar <可疑文件>
```

### 3. 封 C2

```powershell
New-NetFirewallRule -DisplayName "Block XWorm C2" -Direction Outbound `
  -RemoteAddress 109.120.139.126 -Action Block -Profile Any
```

---

## 核心结论

这个病毒不是单纯挖矿，是「肉鸡管理系统」：

```
上线后先做体检：
  显卡型号（Win32_VideoController）
  CPU / 内存
  有没有管理员权限
  装了什么杀毒软件
  用户有没有在用电脑（GetLastInputTime）

然后把报告发给 C2（荷兰防弹主机）
黑客看完再决定：
  显卡好 → 派去挖矿
  显卡差 → 派去 DDoS / 代理跳板 / 键盘记录 / 干脆转卖
```

---

## 传播方式

```
Bing 搜索"软件名" → 点进仿冒官网（AI 做的，长得一模一样）
→ 下载安装包（真软件能用，但捆了恶意组件）
→ 安装后释放 PowerShell 加载器
→ 12 层加密解开 → RunPE 注入 RegAsm.exe（微软合法工具）
→ XWorm 上线
```

**目前仍在活动**：C2 端口 2026-11-10 探测仍开放。

---

## 免责

全部为静态分析，样本未在任何环境执行。
IOC 域名/IP 已做 defang 处理（`[.]`），复制使用时请自行去掉。
