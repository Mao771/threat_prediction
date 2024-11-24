import os

from capstone import *
from capstone.x86 import *
import pefile
import re
import random
import pandas as pd


# the function takes two arguments, both are fetched from the exe file using
# pefile. the first one is the list of all sections. The second one is the
# address of the first instruction in the program
def get_main_code_section(sections, base_of_code):
    addresses = []
    # get addresses of all sections
    for section in sections:
        addresses.append(section.VirtualAddress)

    # if the address of section corresponds to the first instruction then
    # this section should be the main code section
    if base_of_code in addresses:
        return sections[addresses.index(base_of_code)]
    # otherwise, sort addresses and look for the interval to which the base of code
    # belongs
    else:
        addresses.append(base_of_code)
        addresses.sort()
        if addresses.index(base_of_code) != 0:
            return sections[addresses.index(base_of_code) - 1]
        else:
            # this means we failed to locate it
            return None


def fine_disassemble(exe):
    result = ""
    #get main code section
    main_code = get_main_code_section(exe.sections, exe.OPTIONAL_HEADER.BaseOfCode)
    #define architecutre of the machine
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    last_address = 0
    last_size = 0
    #Beginning of code section
    begin = main_code.PointerToRawData
    #the end of the first continuous bloc of code
    end = begin+main_code.SizeOfRawData
    while True:
        #parse code section and disassemble it
        data = exe.get_memory_mapped_image()[begin:end]
        for i in md.disasm(data, begin):
            result += i
            last_address = int(i.address)
            last_size = i.size
        #sometimes you need to skip some bytes
        begin = max(int(last_address), begin)+last_size+1
        if begin >= end:
            print("out")
            break


def disassemble_exe(exe_file_path):
    try:
        # parse exe file
        exe = pefile.PE(exe_file_path)
        try:
            # call the function we created earlier
            return fine_disassemble(exe)
        except:
            print(f'something is wrong with {exe_file_path}')
    except:
        print('pefile cannot parse this file')


def parse_pe(file_name):
    pe = pefile.PE(file_name)

    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    data = pe.get_memory_mapped_image()[entry_point:]

    cs = Cs(CS_ARCH_X86, CS_MODE_32)

    # return [re.sub("0x[0-9a-zA-Z]{4,8}", '', f"{i.mnemonic} {i.op_str}") for i in cs.disasm(data, 0x1000)]
    return [f"{i.mnemonic} " for i in cs.disasm(data, 0x1000)]


def parse_pe_imports(file_name):
    try:
        pe = pefile.PE(file_name)

        pe.parse_data_directories()

        return " ".join([f"{entry.dll.decode()}_{imp.name.decode()}" if imp.name else "" for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports])
    except Exception as e:
        # print(e)
        return "FAILED TO PARSE"

    # for entry in pe.DIRECTORY_ENTRY_IMPORT:
    #     print(entry.dll)
    #     for imp in entry.imports:
    #         print('\t', hex(imp.address), imp.name)


if __name__ == '__main__':
    # create csv with parsed folder
    result = []
    for file in os.listdir('exes'):
        virus_type = random.choice(['Trojan:Win32', 'Backdoor:Win32', 'PUA:Win32'])
        try:
            parsed_pe = parse_pe(f'exes/{file}')
        except Exception as e:
            print(str(e))
            continue
        result.append([parsed_pe, virus_type])

    for file in os.listdir('dlls-safe')[:300]:
        try:
            parsed_pe = parse_pe(f'dlls-safe/{file}')
        except Exception as e:
            print(str(e))
            continue
        result.append([parsed_pe, 'not a virus'])

    for file in os.listdir('exes-safe'):
        try:
            parsed_pe = parse_pe(f'exes-safe/{file}')
        except Exception as e:
            print("EXE FAILED TO PARSE", str(e))
            continue
        result.append([parsed_pe, 'not a virus'])

    result_df = pd.DataFrame(result)
    result_df.to_csv('pe_files_random.csv')
