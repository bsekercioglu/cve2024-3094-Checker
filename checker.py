import subprocess
import os
import re

# Fonksiyon tanımları
def check_for_cve_2024_3094_vulnerability():
    print("Checking system for CVE-2024-3094 Vulnerability...")
    print("https://nvd.nist.gov/vuln/detail/CVE-2024-3094")

    # SSHD'nin kullandığı liblzma'nın yolunu bulma
    sshd_path = subprocess.run(['whereis', '-b', 'sshd'], stdout=subprocess.PIPE, text=True).stdout.split()[1]
    sshd_ldd_output = subprocess.run(['ldd', sshd_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout

    path = ''
    for line in sshd_ldd_output.split('\n'):
        if 'liblzma' in line:
            path = line.split()[2]
            break

    if not path:
        print("\nProbably not vulnerable (liblzma not found)")
        return

    # liblzma'daki fonksiyon imzasını kontrol etme
    print("\nChecking for function signature in liblzma...")
    with open(path, 'rb') as f:
        hex_dump = f.read().hex()

    if 'f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410' in hex_dump:
        print("Function signature in liblzma: VULNERABLE")
    else:
        print("Function signature in liblzma: OK")

    # xz sürümünü kontrol etme
    print("\nChecking xz version...")
    xz_version = subprocess.run(['xz', '--version'], stdout=subprocess.PIPE, text=True).stdout.split('\n')[0].split()[3]
    if xz_version in ["5.6.0", "5.6.1"]:
        print(f"xz version {xz_version}: VULNERABLE")
    else:
        print(f"xz version {xz_version}: OK")

# Ana kod kısmı
if __name__ == "__main__":
    check_for_cve_2024_3094_vulnerability()
