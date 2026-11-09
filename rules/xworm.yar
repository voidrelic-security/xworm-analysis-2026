/*
  规则集：XWorm RAT（经 PowerShell 多层加密 + RunPE 投递）
  来源：实样本逆向（2026-11-10）
  样本链：
    payload.ps1（12 层加密）
      → Gzip
      → XWorm RAT (VB.NET, 33KB)
      → RunPE 注入 RegAsm.exe
*/

rule XWorm_RAT_Config_Strings
{
    meta:
        description = "XWorm RAT 配置字符串特征（分隔符 + 密钥格式 + 命令集）"
        author = "Omp-line"
        date = "2026-11-10"
        severity = "high"
        reference = "实样本 final_payload.bin（SHA256 0eec5978...）"

    strings:
        // XWorm 家族标志分隔符
        $spl = "<Xwormmm>" ascii wide nocase
        // 密钥格式（形如 <V74PV74PV74P>）
        $keyfmt = /<[A-Za-z0-9]{8,24}>/ ascii wide
        // XWorm 命令集（独有组合）
        $c1 = "StartDDos" ascii wide
        $c2 = "StopDDos" ascii wide
        $c3 = "RunShell" ascii wide
        $c4 = "sendPlugin" ascii wide
        $c5 = "savePlugin" ascii wide
        $c6 = "OfflineGet" ascii wide
        $c7 = "OfflineKeylogger Not Enabled" ascii wide
        $c8 = "PCShutdown" ascii wide
        $c9 = "PCRestart" ascii wide
        $c10 = "Urlhide" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $spl or
            (3 of ($c*)) or
            ($keyfmt and 2 of ($c*))
        )
}


rule XWorm_RAT_Hardware_Recon
{
    meta:
        description = "XWorm 硬件指纹采集特征（判断是否值得挖矿）"
        author = "Omp-line"
        date = "2026-11-10"
        severity = "medium"

    strings:
        $w1 = "SELECT * FROM Win32_VideoController" ascii wide
        $w2 = "Win32_Processor.deviceid=" ascii wide
        $w3 = "Select * from AntivirusProduct" ascii wide
        $w4 = "\\root\\SecurityCenter2" ascii wide
        $w5 = "GetLastInputTime" ascii wide
        $w6 = "EXECUTION_STATE" ascii wide

    condition:
        uint16(0) == 0x5A4D and 3 of them
}


rule PS1_XWorm_Loader_Multilayer
{
    meta:
        description = "PowerShell 多层加密加载器（4 步预处理 + 5 层 + AES + RunPE）"
        author = "Omp-line"
        date = "2026-11-10"
        severity = "high"

    strings:
        // 混淆手法
        $o1 = "FromBa`se64String" ascii
        $o2 = "IO.Comp\"+\"ression.G\"+\"ZipStream" ascii
        $o3 = "Reflection.Assembly]::Load" ascii
        $o4 = "RunPE" ascii
        // 注入目标
        $t1 = "RegAsm.exe" ascii wide
        // 自删除
        $d1 = "Remove-Item -LiteralPath $PSCommandPath" ascii

    condition:
        $o1 and $o3 and ($o4 or $t1) and ($o2 or $d1 or $o1)
}


rule C2_XWorm_DuckDNS_AEZA
{
    meta:
        description = "已知 XWorm C2 基础设施（DuckDNS + AEZA 防弹主机）"
        author = "Omp-line"
        date = "2026-11-10"
        severity = "critical"
        c2_domain = "remremrem2021marzo2021.duckdns.org"
        c2_ip = "109.120.139.126"
        c2_port = "3009"
        asn = "AS210644 AEZA GROUP LLC"

    strings:
        $d = "remremrem2021marzo2021.duckdns.org" ascii wide nocase
        $k = "<V74PV74PV74PV74PV74P>" ascii wide
        $g = "GTA15" ascii wide

    condition:
        any of them
}
