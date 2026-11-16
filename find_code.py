import pefile
from capstone import *

# Load file PE
pe = pefile.PE("LinuxLoader-so51a.pe")
image_base = pe.OPTIONAL_HEADER.ImageBase

# Ambil section .text (tempat kode program)
text_sec = [s for s in pe.sections if b".text" in s.Name][0]
code = text_sec.get_data()
text_rva = text_sec.VirtualAddress

# Setup Capstone buat ARM64
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

# Target page dari string "download:" (0x89618 -> page 0x89000)
target_page = 0x89000
target_offset = 0x618

print(f"[*] Mencari instruksi yang nunjuk ke halaman 0x{target_page:X}...")

count = 0
for i in md.disasm(code, image_base + text_rva):
    if i.mnemonic == 'adrp':
        try:
            # Ambil nilai operand kedua (contoh: #0x89000)
            op2 = i.op_str.split(', ')[1].replace('#', '')
            val = int(op2, 16)
            
            if val == target_page:
                print(f"[+] Ketemu ADRP di alamat kode 0x{i.address:X}: {i.mnemonic} {i.op_str}")
                count += 1
        except Exception:
            pass

if count == 0:
    print("[-] Nggak nemu instruksi ADRP yang nunjuk ke 0x89000.")
else:
    print(f"[*] Selesai. Ketemu {count} instruksi. Catat alamat kodenya!")
