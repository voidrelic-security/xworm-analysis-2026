# -*- coding: utf-8 -*-
"""
挖矿病毒自查脚本（只读检测，不删除任何东西）
针对家族：SEO 钓鱼 + ScreenConnect + SRBMiner/gminer/lolMiner + 凭据收割
情报来源：MS Security Blog 2026-05-26 + L 站 3144360 / 2984753

用法：
  python check_miner_virus.py            # 检测模式（只读）
  python check_miner_virus.py --json     # 输出 JSON
"""
import subprocess
import sys
import os
import re
import json

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# ── IOC 清单（来自微软博客 + 受害者实录）─────────────────
SUSPECT_PROCS = [
    "SRBMiner-MULTI.exe", "lolMiner.exe", "gminer.exe", "miner.exe",
    "ccv.exe", "mzcv.exe", "SimpleRunPE.exe",
    "CookieHarvester", "DiscordHarvester", "CursorHarvester", "ClaudeHarvester",
]
# 这些是合法系统进程名，但要检查是否被劫持（路径/父进程异常）
HIJACK_TARGETS = [
    "SecurityHealthHost.exe", "RuntimeHost.exe", "InstallUtil.exe",
    "AppLaunch.exe", "AddInProcess.exe", "aspnet_compiler.exe",
    "GameBox.exe",
]
SUSPECT_DOMAINS = ["minemine.gleeze.com"]
SUSPECT_PORTS = [4041]          # PRL 矿池 relay
SUSPECT_FILES = ["autorun.dll", "SCEA23.tmp"]


def ps(cmd, timeout=40):
    """跑 PowerShell，无黑框；用 GBK 解码避免中文乱码"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        raw = r.stdout or b""
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return raw.decode(enc).strip()
            except Exception:
                continue
        return raw.decode("utf-8", errors="replace").strip()
    except Exception as e:
        return f"__ERR__{e}"


def check_processes():
    out = []
    # 用 Get-CimInstance（不用 wmic，避免弹黑框）
    raw = ps("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,ParentProcessId,CommandLine | ConvertTo-Json -Compress")
    if raw.startswith("__ERR__"):
        return [{"error": raw}]
    try:
        procs = json.loads(raw) if raw else []
        if isinstance(procs, dict):
            procs = [procs]
    except Exception:
        return [{"error": "解析进程列表失败"}]

    for p in procs:
        name = (p.get("Name") or "")
        path = (p.get("ExecutablePath") or "")
        cmdline = (p.get("CommandLine") or "")
        # 1. 直接命中矿工/收割器
        for s in SUSPECT_PROCS:
            if s.lower() in name.lower():
                out.append({"level": "HIGH", "type": "suspect_process",
                            "name": name, "pid": p.get("ProcessId"), "path": path})
        # 2. 合法进程名但路径可疑（不在 System32/SysWOW64）
        for s in HIJACK_TARGETS:
            if s.lower() == name.lower():
                low = path.lower()
                legit = ("\\system32\\" in low) or ("\\syswow64\\" in low) or ("\\microsoft.net\\" in low)
                if path and not legit:
                    out.append({"level": "HIGH", "type": "hijacked_name",
                                "name": name, "pid": p.get("ProcessId"), "path": path})
                elif not path:
                    out.append({"level": "MED", "type": "no_path",
                                "name": name, "pid": p.get("ProcessId")})
        # 3. 命令行里出现可疑端口/域名
        for d in SUSPECT_DOMAINS:
            if d in cmdline:
                out.append({"level": "HIGH", "type": "c2_in_cmdline", "name": name, "cmdline": cmdline[:200]})
        for port in SUSPECT_PORTS:
            if re.search(rf"[:\s]{port}\b", cmdline):
                out.append({"level": "MED", "type": "mining_port_cmdline",
                            "name": name, "cmdline": cmdline[:200]})
    return out


def check_defender_exclusions():
    """Defender 排除项：区分「开发白名单」和「恶意排除项」
    恶意特征：排除的是可执行文件名（而非目录）、且名字伪装成系统进程
    """
    raw = ps("(Get-MpPreference).ExclusionPath; (Get-MpPreference).ExclusionProcess")
    if raw.startswith("__ERR__"):
        return [{"error": raw}]
    lines = [l.strip() for l in raw.split("\n") if l.strip()]

    findings = []
    suspicious = []
    for l in lines:
        low = l.lower()
        base = os.path.basename(low)
        # 排除项是文件（有扩展名），且名字在我们关注列表里 → 高危
        if base and "." in base:
            for s in SUSPECT_PROCS + HIJACK_TARGETS:
                if base == s.lower():
                    suspicious.append(l)
                    break
        # 排除项指向 Temp/ProgramData 下的可执行文件
        elif ("\\temp\\" in low or "\\programdata\\" in low) and base.endswith(".exe"):
            suspicious.append(l)

    if suspicious:
        findings.append({"level": "HIGH", "type": "malicious_exclusion",
                         "count": len(suspicious), "items": suspicious[:10]})

    # 单纯数量多（>50）但都是目录 → 只报 INFO，不判高危
    if len(lines) > 50:
        findings.append({"level": "INFO", "type": "many_exclusions",
                         "count": len(lines),
                         "note": "数量偏多但都是目录路径，多为开发白名单"})
    elif len(lines) > 0:
        findings.append({"level": "INFO", "type": "exclusions_present",
                         "count": len(lines)})
    return findings


def check_screenconnect():
    """ScreenConnect 服务/客户端（合法工具，被滥用为远控）"""
    raw = ps("Get-Service | Where-Object {$_.Name -like '*ScreenConnect*' -or $_.DisplayName -like '*ScreenConnect*'} | Select-Object Name,DisplayName,Status | ConvertTo-Json -Compress")
    if raw.startswith("__ERR__"):
        return [{"error": raw}]
    if raw and raw not in ("[]", "null"):
        return [{"level": "MED", "type": "screenconnect_present", "detail": raw[:300]}]
    return []


def check_network():
    """可疑外连"""
    raw = ps("Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress")
    if raw.startswith("__ERR__"):
        return [{"error": raw}]
    out = []
    try:
        conns = json.loads(raw) if raw else []
        if isinstance(conns, dict):
            conns = [conns]
    except Exception:
        return out
    for c in conns:
        rp = c.get("RemotePort")
        ra = c.get("RemoteAddress") or ""
        if rp in SUSPECT_PORTS:
            out.append({"level": "HIGH", "type": "mining_port_conn",
                        "remote": f"{ra}:{rp}", "pid": c.get("OwningProcess")})
    return out


def check_files():
    """可疑文件名（autorun.dll 侧加载 / SCEA23.tmp）"""
    out = []
    roots = [os.environ.get("PROGRAMDATA", ""), os.environ.get("TEMP", ""),
             os.environ.get("LOCALAPPDATA", "")]
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > 4:
                dirnames[:] = []
                continue
            for f in filenames:
                for s in SUSPECT_FILES:
                    if f.lower() == s.lower():
                        out.append({"level": "MED", "type": "suspect_file",
                                    "path": os.path.join(dirpath, f)})
            if len(out) > 30:
                return out
    return out


def check_runlog():
    """run.log 里是否有 MINER_START（受害者实录里的关键证据）"""
    out = []
    roots = [os.environ.get("PROGRAMDATA", ""), os.path.expanduser("~")]
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > 3:
                dirnames[:] = []
                continue
            for f in filenames:
                if f.lower() == "run.log":
                    p = os.path.join(dirpath, f)
                    try:
                        if os.path.getsize(p) > 5 * 1024 * 1024:
                            continue
                        txt = open(p, encoding="utf-8", errors="ignore").read()
                        if "MINER_START" in txt or "relay1:" in txt:
                            out.append({"level": "HIGH", "type": "miner_log",
                                        "path": p,
                                        "hit": [l for l in txt.split("\n") if "MINER_START" in l][:3]})
                    except Exception:
                        pass
    return out


def main():
    as_json = "--json" in sys.argv
    print("=" * 62)
    print(" 挖矿病毒自查（只读，不做任何修改）")
    print("=" * 62)

    checks = [
        ("进程检查", check_processes),
        ("Defender 排除项", check_defender_exclusions),
        ("ScreenConnect", check_screenconnect),
        ("网络连接", check_network),
        ("可疑文件", check_files),
        ("run.log 挖矿日志", check_runlog),
    ]

    all_findings = []
    for name, fn in checks:
        print(f"\n[ ] {name} ...", end="", flush=True)
        try:
            res = fn()
        except Exception as e:
            res = [{"level": "ERR", "type": "check_failed", "detail": str(e)[:120]}]
        print(f" {len(res)} 项")
        for r in res:
            all_findings.append(r)
            lvl = r.get("level", "?")
            mark = {"HIGH": "!!", "MED": " !", "ERR": " ?"}.get(lvl, "  ")
            detail = {k: v for k, v in r.items() if k != "level"}
            if not as_json:
                print(f"  {mark} [{lvl}] {detail}")

    high = [f for f in all_findings if f.get("level") == "HIGH"]
    print("\n" + "=" * 62)
    if high:
        print(f" 结论：发现 {len(high)} 项高危，建议人工确认后处理")
    else:
        print(" 结论：未发现已知 IOC 命中")
    print("=" * 62)

    if as_json:
        print(json.dumps({"findings": all_findings, "high_count": len(high)},
                         ensure_ascii=False, indent=1))
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
