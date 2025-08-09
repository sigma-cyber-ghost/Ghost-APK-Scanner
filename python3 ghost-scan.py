#!/usr/bin/env python3
import os, sys
from lxml import etree
from androguard.misc import AnalyzeAPK
from datetime import datetime

# Terminal colors
RED, GREEN, YELLOW, CYAN, ENDC = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[0m'

# Custom Banner
def print_banner():
    print(f"""{CYAN}
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣤⣤⣤⣤⣤⣤⡼⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀
⣠⣄⠀⢠⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡄⠀⣠⣄
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠉⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀
{ENDC}""")

    print(f"""{YELLOW}
╔════════════════════════════════════════════╗
║          ⚡ SIGMA CYBER GHOST ⚡           ║
║        APK Scanner Tool v0.1 Final         ║
╚════════════════════════════════════════════╝
{CYAN}
──────────────────────────────────────────────
[+] Creator  : Sigma Cyber Ghost
[+] Twitter  : https://twitter.com/safderkhan0800_
[+] YouTube  : https://www.youtube.com/@sigma_ghost_hacking
[+] Telegram : https://t.me/Sigma_Cyber_Ghost
[+] GitHub   : https://github.com/sigma-cyber-ghost
──────────────────────────────────────────────
{ENDC}""")

# Define high-risk perms and keywords
DANGEROUS = {
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
}
KEYWORDS = ['token', 'chat_id', 'telegram', 'bot', 'hook', 'exec', 'payload', 'su', 'meterpreter']

def scan_apk(apk_path):
    print(f"{CYAN}[+] Scanning: {apk_path}{ENDC}")
    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print(f"{RED}[!] Failed to analyze APK: {e}{ENDC}")
        return

    permissions = set(a.get_permissions())
    risk_perms = permissions & DANGEROUS
    print(f"\n{YELLOW}Declared Permissions ({len(permissions)}):{ENDC}")
    for p in permissions:
        print(f" └─ {p}")
    print(f"{RED if risk_perms else GREEN}[!] Dangerous Permissions: {', '.join(risk_perms) if risk_perms else 'None'}{ENDC}")

    try:
        manifest_xml = a.get_android_manifest_xml()
        if manifest_xml is not None:
            manifest_raw = etree.tostring(manifest_xml, encoding="unicode")
            print(f"\n{YELLOW}[•] Exported Components:{ENDC}")
            for tag in ["activity", "receiver", "service", "provider"]:
                for comp in manifest_xml.xpath(f"//{tag}"):
                    exp = comp.get('{http://schemas.android.com/apk/res/android}exported')
                    name = comp.get('{http://schemas.android.com/apk/res/android}name')
                    if exp == "true":
                        print(f"{RED} └─ {tag.upper()} → {name} [EXPORTED]{ENDC}")
    except Exception as e:
        print(f"{RED}[!] Failed to parse exported components: {e}{ENDC}")

    print(f"\n{YELLOW}[•] Suspicious Strings Scan:{ENDC}")
    flags = set()
    for method in dx.get_methods():
        if method.is_external(): continue
        try:
            for block in method.get_basic_blocks().get():
                for ins in block.get_instructions():
                    out = ins.get_output().lower()
                    for kw in KEYWORDS:
                        if kw in out:
                            flags.add((kw, method.name))
        except: continue

    if flags:
        for kw, method in flags:
            print(f"{RED} └─ Found keyword '{kw}' in {method}{ENDC}")
    else:
        print(f"{GREEN} └─ No suspicious keywords found.{ENDC}")

    report_file = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(f"Report for {apk_path}\nPermissions:\n")
        for p in permissions:
            f.write(f" - {p}\n")
        f.write("\nDangerous Permissions:\n")
        for p in risk_perms:
            f.write(f" - {p}\n")
        f.write("\nSuspicious Code:\n")
        for kw, method in flags:
            f.write(f" - {kw} in {method}\n")

    print(f"\n{GREEN}[✓] Scan complete. Report saved as: {report_file}{ENDC}")

def main():
    print_banner()
    apk_path = input(f"{CYAN}[?] Enter APK path: {ENDC}").strip().strip('"').strip("'")
    if not os.path.isfile(apk_path):
        print(f"{RED}[X] APK file not found: {apk_path}{ENDC}")
        return
    scan_apk(apk_path)

if __name__ == "__main__":
    main()
