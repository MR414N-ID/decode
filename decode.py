#!/usr/bin/env python3
"""
SC DECODER
BY LANOX
"""

import re
import base64
import sys
from pathlib import Path

# ============================================================
# BANNER
# ============================================================
BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║  ██║█████╗  ██║     ██║   ██║██║  ██║█████╗  
██║  ██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝  
██████╔╝███████╗╚██████╗╚██████╔╝██████╔╝███████╗
╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
"""
FOOTER = "                    by LANOX\n"

HEADER_OFFSET = 1305
OUTDIR = Path("decoded")


def print_banner():
    print("\033[96m" + BANNER + "\033[0m")
    print("\033[90m" + FOOTER + "\033[0m")
    print("\033[90m" + "=" * 56 + "\033[0m\n")


# ============================================================
# CORE
# ============================================================
def extract_octal(path: str) -> bytes:
    text = Path(path).read_text(errors="ignore")
    m = re.search(r"static\s+char\s+data\s*\[\s*\]\s*=(.*?);", text, re.S)
    block = m.group(1) if m else text
    octals = re.findall(r"\\([0-7]{3})", block)
    return bytes(int(o, 8) for o in octals)


def score_plaintext(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if x in b"\t\n\r" or 32 <= x < 127) / len(b)


def try_repeating_xor(data: bytes, max_klen: int = 32):
    results = []
    for klen in range(2, max_klen + 1):
        key = []
        for i in range(klen):
            col = data[i::klen][:256]
            k = max(range(256), key=lambda c: score_plaintext(bytes(x ^ c for x in col)))
            key.append(k)
        dec = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
        s = score_plaintext(dec[:2048])
        results.append((s, klen, bytes(key), dec))
    results.sort(reverse=True, key=lambda x: x[0])
    return results


def find_artifacts(plain: bytes):
    txt = plain.decode("latin-1", errors="ignore")
    urls = re.findall(r"https?://[^\s\"'<>\)]+", txt)
    b64s = re.findall(r"[A-Za-z0-9+/=]{40,}", txt)
    ps = any(t in txt for t in ("$env:", "Invoke-", "New-Object", "Start-Process", "$s ="))
    return urls, b64s, ps


# ============================================================
# MAIN
# ============================================================
def main():
    print_banner()

    # --- prompt input file ---
    print("\033[97mMASUKAN FILE YANG AKAN DI DECODE\033[0m")
    src = input("\033[96m>> \033[0m").strip().strip('"').strip("'")

    if not src:
        print("\033[91m[!] nama file kosong.\033[0m")
        return

    if not Path(src).exists():
        print(f"\033[91m[!] file '{src}' tidak ditemukan.\033[0m")
        return

    OUTDIR.mkdir(exist_ok=True)

    print(f"\n\033[93m[*]\033[0m extracting octal escapes dari \033[97m{src}\033[0m ...")
    raw = extract_octal(src)
    print(f"    raw size: \033[97m{len(raw)}\033[0m bytes")
    (OUTDIR / "01_raw.bin").write_bytes(raw)

    print(f"\033[93m[*]\033[0m dropping header \033[97m{HEADER_OFFSET}\033[0m bytes ...")
    payload = raw[HEADER_OFFSET:] if len(raw) > HEADER_OFFSET else raw
    print(f"    payload size: \033[97m{len(payload)}\033[0m bytes")
    (OUTDIR / "02_payload.bin").write_bytes(payload)

    print("\033[93m[*]\033[0m brute repeating XOR (keylen 2–32) ...")
    results = try_repeating_xor(payload)
    for rank, (s, klen, key, _) in enumerate(results[:3]):
        print(f"    #{rank+1}: klen={klen} key={key!r} score={s:.2f}")

    _, best_klen, best_key, best_dec = results[0]
    (OUTDIR / "03_best_plain.bin").write_bytes(best_dec)
    print(f"\033[92m[+]\033[0m best key: klen={best_klen} key={best_key!r}")

    print("\033[93m[*]\033[0m scanning URLs / base64 / PowerShell ...")
    urls, b64s, ps = find_artifacts(best_dec)
    if urls:
        for u in urls:
            print(f"    \033[96mURL:\033[0m {u}")
    if ps:
        print("    \033[96mPowerShell indicators detected\033[0m")

    for i, b in enumerate(b64s[:5]):
        try:
            dec2 = base64.b64decode(b + "=" * (-len(b) % 4))
            print(f"    \033[96mb64[{i}] ->\033[0m {dec2[:120]!r}")
        except Exception:
            pass

    print(f"\n\033[92m[+]\033[0m selesai. hasil ada di \033[97m./decoded/\033[0m")
    print("\033[90m" + "=" * 56 + "\033[0m")


if __name__ == "__main__":
    main()
