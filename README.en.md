# XWorm RAT — Static Analysis

Analysis of an XWorm RAT delivered through a 12-layer encrypted PowerShell loader,
using Process Hollowing (RunPE) to inject into a legitimate .NET binary.

**All analysis is static. The sample was never executed.**

---

## Summary

```
Loader     42 KB PowerShell script, 12 encryption layers
Payload    33 KB VB.NET (XWorm RAT)
Injection  C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
C2         remremrem2021marzo2021[.]duckdns[.]org:3009
Infra      109[.]120[.]139[.]126  (NL / AS210644 AEZA GROUP LLC)
Family     XWorm (marker: <Xwormmm>)
```

---

## Decryption chain

```
Base64
→ adjacent byte swap
→ bitwise NOT
→ subtract 32-byte key stream
→ bitwise NOT
→ XOR 64-byte stream (with position mixing)
→ triple XOR (61 / 47 / 31-byte keys)
→ bit rotate (ROR, position dependent)
→ 256-byte S-box substitution
→ RC4 (40-byte key)
→ AES-CBC (custom S-box)
→ Gzip
```

Details in [ANALYSIS.md](ANALYSIS.md).

---

## What it actually does

Not a plain miner. It profiles the host first:

```
WMI  Win32_VideoController    GPU model  (decides whether mining is worth it)
WMI  Win32_Processor          CPU
WMI  AntivirusProduct         AV product
API  GetLastInputTime         user idle state
API  ExecutionState           prevents sleep
```

Report goes to C2, which then assigns work: mining, DDoS, proxy relay,
credential theft, or resale.

Command set: `RunShell`, `StartDDos`, `StopDDos`, `OfflineKeylogger`,
`UACFunc`, `plugin`, `PCShutdown`, `Hosts`, `USB.exe`.

---

## Detection

| Artifact | Value |
|---|---|
| C2 domain | `remremrem2021marzo2021[.]duckdns[.]org` |
| C2 IP:port | `109[.]120[.]139[.]126:3009` |
| Payload SHA256 | `0eec59785a5e8816287839806c195a89c50f93a852eb7b3db563d6245478f7c3` |
| Family marker | `<Xwormmm>` |

Traffic containing `<Xwormmm>` can be treated as XWorm.

YARA rules: [`rules/xworm.yar`](rules/xworm.yar) — validated against the real sample.

Self-check script (Windows): [`check_miner_virus.py`](check_miner_virus.py)

---

## Repository layout

```
README.md              this file
ANALYSIS.md            12-layer walkthrough (Chinese)
IOC.md                 indicators, blocking config (Chinese)
check_miner_virus.py   host self-check (read-only)
rules/
  xworm.yar            XWorm detection rules
  screenconnect.yar    ScreenConnect abuse chain rules
```

---

## Reference

- Delivery chain: SEO poisoning of software download pages
  (fake official sites for Hibit Uninstaller, 驱动总裁, 图吧工具箱)
- Related Microsoft research:
  *From poisoned search results to GPU mining: A cryptojacking campaign
  abusing ScreenConnect and Microsoft .NET utilities* (2026-05-26)

---

Statically analyzed. No sample execution performed.
