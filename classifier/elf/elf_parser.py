import os
import traceback

from elftools.elf.elffile import ELFFile
from capstone import *


def parse_file(file_obj: str, section_name: str = '.text') -> list:
    if isinstance(file_obj, str):
        with open(file_obj, "rb") as f:
            try:
                elf = ELFFile(f)
                code = elf.get_section_by_name(section_name)
                ops = code.data()
                addr = code['sh_addr']
                md = Cs(CS_ARCH_X86, CS_MODE_64)

                return [f"{i.mnemonic}{i.op_str}".replace(" ", "") for i in md.disasm(ops, addr)]
            except Exception as e:
                print(str(e))


def parse_file_segments(file_obj) -> list:
    file_size = os.path.getsize(file_obj) / (10**6)

    if file_obj == '/home/max/Downloads/VirusShare_ELF_20200405/VirusShare_213cb67fa891ca0068aa59ceb0017c83':
        b = 2
        print("Wow")

    print(f"File {file_obj} size is {file_size}")
    if file_size > 30:
        print(f"File {file_obj} is too big. skipping")
        return []
    with open(file_obj, "rb") as f:
        try:
            elf = ELFFile(f)
            segment_commands = []
            for segment in elf.iter_segments():
                segment_data = segment.data()
                addr = segment.header["p_paddr"]
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                for i in md.disasm(segment_data, addr):
                    segment_commands.append(f'{i.mnemonic}{i.op_str}'.replace(" ",""))
        except Exception as e:
            print(e)

    return segment_commands


ELF_PARSER_DIR = "D:\Documents\VirusShare_ELF_20200405"

if __name__ == '__main__':
    # for file in os.listdir(ELF_PARSER_DIR):
    #     with open(f"{ELF_PARSER_DIR}\\{file}", 'rb') as f:
    #         try:
    #             elf = ELFFile(f)
    #             code = elf.get_section_by_name('.text')
    #             ops = code.data()
    #             addr = code['sh_addr']
    #             md = Cs(CS_ARCH_X86, CS_MODE_64)
    #             print(f'{file} - {" ".join([f"{i.mnemonic} {i.op_str}" for i in md.disasm(ops, addr)])}')
    #             # for i in md.disasm(ops, addr):
    #             #     print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
    #         except Exception as e:
    #             print(str(e))

    for file in os.listdir(ELF_PARSER_DIR):
        with open(f"{ELF_PARSER_DIR}\\{file}", "rb") as f:
            try:
                elf = ELFFile(f)
                for segment in elf.iter_segments():
                    segment_data = segment.data()
                    addr = segment.header["p_paddr"]
                    md = Cs(CS_ARCH_X86, CS_MODE_64)
                    for i in md.disasm(segment_data, addr):
                        print(f'{i.mnemonic}{i.op_str}')
            except Exception as e:
                traceback.print_exc()
