import os
import arguably


@arguably.command
def scan(
    filename: str,
    *,
    no_checksec: bool = False,
    no_strings: bool = False,
    no_file_details: bool = False,
    no_disassembly: bool = False,
    no_ldd: bool = False,
    no_rop: bool = False,
    no_elf_analysis: bool = False,
    no_seccomp: bool = False,
    no_gdb: bool = False,
    no_pwn_check: bool = False,
):
    """
    Scans a binary file for initial vulnerability assessment in CTF challenges.

    Args:
        filename: The binary to scan.
        no_checksec: Skip checksec analysis.
        no_strings: Skip extracting strings from the binary.
        no_file_details: Skip displaying file details.
        no_disassembly: Skip binary disassembly.
        no_ldd: Skip linked library checks.
        no_rop: Skip ROP gadget search.
        no_elf_analysis: Skip ELF header analysis.
        no_seccomp: Skip seccomp analysis.
        no_gdb: Skip initial gdb inspection.
        no_pwn_check: Skip additional checks for pwn-specific setups.
    """
    print(f"Scanning file: {filename}")

    if not no_file_details:
        print("\n[+] File Details:")
        os.system(f"file {filename}")

    if not no_strings:
        print("\n[+] Extracting Strings:")
        os.system(f"strings {filename} | head -n 20")

    if not no_checksec:
        print("\n[+] Running Checksec:")
        os.system(f"checksec --file={filename}")

    if not no_disassembly:
        print("\n[+] Disassembling the Binary (First 20 Instructions):")
        os.system(f"objdump -d {filename} | head -n 40")

    if not no_ldd:
        print("\n[+] Checking Linked Libraries:")
        os.system(f"ldd {filename}")

    if not no_rop:
        print("\n[+] Searching for ROP Gadgets:")
        os.system(f"ROPgadget --binary {filename} | head -n 20")

    if not no_elf_analysis:
        print("\n[+] Analyzing ELF Headers:")
        os.system(f"readelf -a {filename} | head -n 40")

    if not no_seccomp:
        print("\n[+] Checking Seccomp Rules:")
        os.system(f"seccomp-tools dump ./{filename}")

    if not no_gdb:
        print("\n[+] GDB Initial Analysis:")
        os.system(f"gdb -q -ex 'file {filename}' -ex 'info functions' -ex 'quit'")

    if not no_pwn_check:
        print("\n[+] Checking Binary with Pwntools:")
        os.system(f"pwn checksec {filename}")

    print("\n[+] Scan Completed.")


if __name__ == "__main__":
    arguably.run()
