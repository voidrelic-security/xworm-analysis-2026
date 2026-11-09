# 拆解过程（大白话 + 技术细节）

> 一个 42KB 的 PowerShell 脚本，里面套了 12 层加密。
> 这篇讲怎么一层层剥开，以及每层在防什么。

---

## 先说人话

```
这个脚本就像快递：

外层纸箱       → Base64（谁都会拆）
里面气泡膜     → 字节交换 + 取反（防肉眼看）
再里面泡沫     → 减密钥流（防直接读）
再里面塑料袋   → XOR 多层（防静态分析）
再里面钢板     → 位旋转 + S-box（防自动化工具）
最里面密封箱   → RC4 + AES（真加密）
最后压缩包     → Gzip
里面才是真东西 → XWorm 木马
```

**为什么要套这么多层？**
不是技术高明，是「拖时间 + 骗杀软」：
- 杀软静态扫描看不懂
- 自动化工具（比如 de4dot）认不出来
- 人工分析的人嫌麻烦就放弃了

---

## 逐层拆解

### 第 1 步：Base64（最简单）

```powershell
$e = [Convert]::FromBase64String($encPayload)
```

解码后 17,152 字节。**这一步谁都会，真正的门槛在后面。**

---

### 第 2-5 步：预处理（最容易漏的）

```powershell
# 相邻字节两两交换
for($i=0;($i+1) -lt $e.Length;$i+=2){$t=$e[$i];$e[$i]=$e[$i+1];$e[$i+1]=$t}

# 取反
for($i=0;$i -lt $e.Length;$i++){$e[$i]=[byte]((-bnot $e[$i]) -band 0xFF)}

# 减密钥流
for($i=0;$i -lt $e.Length;$i++){$e[$i]=[byte](($e[$i] - $_pk0[$i%32]) -band 0xFF)}

# 再取反
for($i=0;$i -lt $e.Length;$i++){$e[$i]=[byte]((-bnot $e[$i]) -band 0xFF)}
```

**我第一遍就漏了这 4 步**，直接跳到后面的 XOR，结果全是乱码。

这 4 步的作用：把数据搅乱，让「看起来像正常二进制」这个判断失效。

---

### 第 6-7 步：多层 XOR

```powershell
# 64 字节循环 + 位置混合（每字节 XOR 的值跟它的位置有关）
for($i=0;$i -lt $e.Length;$i++){
  $e[$i]=$e[$i] -bxor ([byte]($_vm16[$i%64] -bxor [byte]($i -band 0xFF) -bxor [byte](($i -shr 8) -band 0xFF)))
}

# 三重 XOR（61/47/31 三个不同长度的密钥交替）
for($i=0;$i -lt $e.Length;$i++){
  $e[$i]=$e[$i] -bxor $_vc15[$i%61] -bxor $_vb14[$i%47] -bxor $_va13[$i%31]
}
```

**为什么要三个不同长度？**
因为 61/47/31 三个数互质，`i % 61`、`i % 47`、`i % 31` 的组合周期是 61×47×31 = 88,727。

也就是说：**密钥流要 8 万多字节才重复一次**，而文件只有 1.7 万字节。

→ 整份文件里没有重复模式 → 自动化解密工具找不到规律。

---

### 第 8 步：位旋转（ROR）

```powershell
$r = ($_vt12[$i%128] + $i) -band 7
if($r -gt 0){ $e[$i] = [byte]((($e[$i] -shr $r) -bor ($e[$i] -shl (8-$r))) -band 0xFF) }
```

每个字节按不同位数循环右移。**旋转位数还跟位置相关**（`+$i`），又加了一层复杂度。

---

### 第 9 步：S-box 替换

```powershell
for($i=0;$i -lt $e.Length;$i++){$e[$i]=$_vs11[$e[$i]]}
```

256 字节的替换表，每个字节值查表换成另一个值。

**这是 AES 的经典手法**（S-box 就是 AES 里的替换表），用在这里增加非线性。

---

### 第 10 步：RC4

```powershell
# 标准 RC4：KSA 初始化 + PRGA 生成密钥流
$S=[byte[]]::new(256); for($i=0;$i -lt 256;$i++){$S[$i]=[byte]$i}
$j=0
for($i=0;$i -lt 256;$i++){
  $j=($j+$S[$i]+$_vr10[$i%40]) -band 0xFF
  $t=$S[$i];$S[$i]=$S[$j];$S[$j]=$t
}
$a=0;$b=0
for($n=0;$n -lt $e.Length;$n++){
  $a=($a+1) -band 0xFF
  $b=($b+$S[$a]) -band 0xFF
  swap($S[$a],$S[$b])
  $e[$n]=$e[$n] -bxor $S[($S[$a]+$S[$b]) -band 0xFF]
}
```

**这是标准 RC4**，40 字节密钥。识别特征：`$S[($S[$a]+$S[$b]) & 0xFF]` 这个索引方式。

Python 里 10 行就能复现。

---

### 第 11 步：加密的 AES（这里有个坑）

脚本里藏了一个 11KB 的 .NET 程序集：

```powershell
$_qa54 = [Convert]::FromBase64String('XEuBERIR...')
for($_i=0;$_i-lt$_qa54.Length;$_i++){$_qa54[$_i]=$_qa54[$_i]-bxor 17}
$qd=[Reflection.Assembly]::Load($_qa54)
```

解开后是合法的 PE（MZ + BSJB），反编译看到：

```
Qwrpivbc8              主类
DCreateProcessA        P/Invoke
DVirtualAllocEx
DWriteProcessMemory
DNtUnmapViewOfSection  ← Process Hollowing 关键 API
```

**这是 RunPE 实现**（把 PE 注入到别的进程里跑）。

它的 `D()` 方法是解密函数，但**不是标准 AES**：
- Key 是 16 字节
- 但 S-box 被替换成了自定义的 256 字节表
- 所以我用标准 AES 库解不开

**解决办法**：不自己实现，直接反射调用它的 `D()` 方法。

```python
# pythonnet
asm = Assembly.LoadFile('decryptor.dll')
out = asm.GetType('Qwrpivbc8').GetMethod('D').Invoke(None, [cipher, key1, key2])
```

**前提**：先看 IL 确认 `D()` 是纯函数（只调 S/E/BlockCopy，不碰文件/网络/进程）。确认了才敢调。

---

### 第 12 步：Gzip

```python
final = gzip.decompress(out)
```

33,280 字节 —— **真家伙出来了。**

---

## 拆出来的东西

```
不是挖矿程序，是 XWorm 远程控制木马（VB.NET）

查看类名就知道功能：
  ClientSocket      连 C2
  AlgorithmAES      加密通信
  Messages          指令分发
  Uninstaller       自卸载
  LASTINPUTINFO     检测用户空闲
  EXECUTION_STATE   阻止系统休眠
```

配置也是加密的，从 `.cctor` 里读出来：

| 字段 | 解密后 |
|---|---|
| Hosts | `remremrem2021marzo2021[.]duckdns[.]org` |
| Port | `3009` |
| KEY | `<V74PV74PV74PV74PV74P>` |
| SPL | `<Xwormmm>`（家族标志） |
| Groub | `GTA15` |

---

## 它的用途（关键判断）

```
它不直接挖矿，它先"体检"：

  WMI 查显卡型号  → SELECT * FROM Win32_VideoController
  WMI 查 CPU      → Win32_Processor.deviceid="CPU0"
  WMI 查杀软      → Select * from AntivirusProduct
  API 查空闲      → GetLastInputTime

报告发给 C2，黑客按配置派活：
  显卡好 → 挖矿
  显卡差 → DDoS / 代理 / 键盘记录 / 转卖
```

**所以「休眠挖矿」只是它其中一种业务。**

---

## 踩过的坑

```
① 别急着说"加壳"
   节表完整、没有 UPX 特征，高熵是加密造成的

② de4dot 3.1（2015）对现代 .NET 基本无效
   只报 "Unknown Obfuscator"

③ MalwareBazaar 的 zip 是 AES 加密
   Python 标准 zipfile 解不了，要 pyzipper

④ 样本别在 Windows 上下
   Defender 静默删除，连日志都不留

⑤ 反射调用程序集之前，先看 IL 确认纯函数
```

---

## 方法论总结

```
多层加密样本的静态拆解套路：

1. 先找主载荷定义（@'...'@）
2. 找所有密钥数组（base64 或 @(数字)）
3. 按顺序读解密代码，注意预处理在前
4. 提取隐藏的 .NET 程序集（base64 + 简单 XOR）
5. 反编译 IL 确认算法（monodis / dncil）
6. Python 复现（pycryptodome）
7. 算法太复杂就反射调用原方法

全程不需要运行样本。
```
