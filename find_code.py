import pefile
from capstone import *

pe = pefile.PE("LinuxLoader-so51a.pe")
image_base = pe.OPTIONAL_HEADER.ImageBase
text_sec = [s for s in pe.sections if b".text" in s.Name][0]
code = text_sec.get_data()
text_rva = text_sec.VirtualAddress

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

target_page = 0x89000
target_offset = 0x618
target_addr = target_page + target_offset

print(f"[*] Mencari referensi persis ke alamat 0x{target_addr:X} (teks 'download:')...")

# Disassemble semua instruksi ke dalam list biar gampang di-look-ahead
instructions = list(md.disasm(code, image_base + text_rva))

count = 0
for idx, i in enumerate(instructions):
    if i.mnemonic == 'adrp':
        try:
            op2 = i.op_str.split(', ')[1].replace('#', '')
            val = int(op2, 16)
            if val == target_page:
                reg = i.op_str.split(',')[0].strip()
                # Cek 4 instruksi ke depan, cari ADD yang nambahin 0x618
                for j in range(1, 5):
                    if idx + j < len(instructions):
                        next_i = instructions[idx + j]
                        if next_i.mnemonic == 'add' and reg in next_i.op_str.split(',')[0]:
                            if '#0x618' in next_i.op_str or '#0x618]' in next_i.op_str or '#0x618 ' in next_i.op_str:
                                print(f"\n[+] KETEMU! Ini fungsi yang nanganin perintah 'download:'")
                                print(f"    Alamat ADRP : 0x{i.address:X} ({i.mnemonic} {i.op_str})")
                                print(f"    Alamat ADD  : 0x{next_i.address:X} ({next_i.mnemonic} {next_i.op_str})")
                                count += 1
        except Exception:
            pass

if count == 0:
    print("[-] Nggak nemu pasangan ADRP+ADD yang persis nunjuk ke 0x89618.")
else:
    print(f"\n[*] Selesai. Ketemu {count} referensi persis.")
