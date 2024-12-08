import json

from elf_parser import parse_file
import pandas as pd
import os
import re
from itertools import groupby

FAILED_TO_DISASSEMBLE = "Failed to disassemble"
OPCODES_COLUMN = "processed_opcodes"
OPCODES_ORIGINAL_COLUMN = "original_opcodes"


def generate_dataset():
    print(pd.read_csv("files_for_test.rodata.csv")['Microsoft'].value_counts())
    existing_df = pd.read_csv("files_new_.rodata.csv")
    existing_ids = existing_df.iloc[:, 0].tolist()
    VIRUS_FOLDER = "/home/max/Downloads/VirusShare_ELF_20190212"
    SECTION_NAME = '.rodata'

    result_fname = "files_new_1.rodata.csv"

    with open("virustotal_elf/virustotal_elf.json") as f:
        virus_analysis = json.load(f)
    viruses_count = len(virus_analysis)
    parsed_count = 0
    files = {}
    index = 0

    for f_name in virus_analysis.keys():
        if f_name in existing_ids:
            print("Skip", f_name)
            continue

        commands = []
        original_commands = []
        try:
            fname = os.path.join(VIRUS_FOLDER, f"VirusShare_{f_name}")
            print(fname)
            file_commands = parse_file(fname, SECTION_NAME)
            for command in file_commands:
                original_commands.append(command)
                text = re.sub("0x[0-9a-zA-Z]{4,8}", '', command)
                commands.append(text)
            parsed_count += 1
        except Exception as e:
            print(f"{f_name} exception {str(e)}")
        except TimeoutError as e:
            print(f"{f_name} parse timeout")
        print(f"parsed: {parsed_count}/{viruses_count}")
        try:
            files[f_name] = {
                "original_opcodes": " ".join(
                    [key for key, _group in groupby(original_commands)]) if original_commands else FAILED_TO_DISASSEMBLE,
                OPCODES_COLUMN: " ".join([key for key, _group in groupby(commands)]) if commands else FAILED_TO_DISASSEMBLE,
                "virus": virus_analysis[f_name]['Microsoft']['result']
            }
        except Exception as e:
            print(f_name)
            raise e
        index += 1


    df = pd.DataFrame.from_dict(data=files, columns=["original_opcodes", OPCODES_COLUMN, 'virus'], orient="index")
    df = df.fillna("")
    df = df.drop(df[df[OPCODES_COLUMN] == FAILED_TO_DISASSEMBLE].index)
    df['virus'] = df['virus'].str.split(":", n=1, expand=True)[1]
    df = df[[OPCODES_COLUMN, "virus"]]
    print(existing_df['virus'].value_counts())
    print(df['virus'].value_counts())
    df = pd.concat(objs=[existing_df, df])
    df.to_csv(result_fname)


def change_labels(only_new: bool = False):
    with open("virustotal_elf/virustotal_elf.json") as f:
        virus_analysis = json.load(f)
    with open("virus_analysis_extended.json") as f:
        virus_analysis_old = json.load(f)

    commands = []
    original_commands = []
    files = {}

    if only_new:
        all_f_names = list(virus_analysis.keys())
    else:
        all_f_names = list(virus_analysis.keys()) + list(virus_analysis_old.keys())
    parsed_count = 0
    viruses_count = len(all_f_names)

    for f_name in all_f_names:
        if f_name == '213cb67fa891ca0068aa59ceb0017c83' or f_name == '828ed525ad53ccfa71c6344cdc02abc4' or f_name == '048eeee73403da99614f40ab5940ac32':
            continue
        print(f_name)
        f_path = os.path.join("/home/max/Downloads/VirusShare_ELF_20190212", f"VirusShare_{f_name}")
        if not os.path.exists(f_path):
            f_path = os.path.join("/home/max/Downloads/VirusShare_ELF_20200405", f"VirusShare_{f_name}")
        try:
            file_commands = parse_file(f_path, ".rodata")
            for command in file_commands:
                original_commands.append(command)
                text = re.sub("0x[0-9a-zA-Z]{4,8}", '', command)
                commands.append(text)
            parsed_count += 1
        except Exception as e:
            print(f"{f_name} exception {str(e)}")
        except TimeoutError as e:
            print(f"{f_name} parse timeout")
        print(f"parsed: {parsed_count}/{viruses_count}")

        try:
            label = virus_analysis[f_name]['Microsoft']['result']
        except KeyError:
            try:
                label = virus_analysis_old[f_name]['Microsoft']['result']
            except KeyError:
                continue
        try:
            files[f_name] = {
                "original_opcodes": " ".join(
                    [key for key, _group in groupby(original_commands)]) if original_commands else FAILED_TO_DISASSEMBLE,
                "processed_opcodes": " ".join([key for key, _group in groupby(commands)]) if commands else FAILED_TO_DISASSEMBLE,
                "virus": label
            }
        except Exception as e:
            print(f_name)
            raise e

    df = pd.DataFrame.from_dict(data=files, columns=[OPCODES_COLUMN, 'virus'], orient="index")
    df.dropna(inplace=True)

    if only_new:
        df.to_csv("elf_new.csv")
    else:
        undetected = pd.read_csv("viruses_rodata_Microsoft_with_undetected.csv")
        undetected = undetected[undetected['virus'] == "undetected"]
        pd.concat([df, undetected]).to_csv("result_elf.csv")


def create_safe():
    commands = []
    parsed_count = 0
    files = {}
    folder = "/home/max/Downloads/Labeled-Elfs-main/benignware"
    # safe_files = os.listdir(folder)
    safe_files = os.listdir(folder)
    safe_count = len(safe_files)
    for filename in safe_files[:4000]:
        if 'obfuscator' in filename:
            continue

        f_path = os.path.join(folder, filename)
        file_commands = parse_file(f_path, ".rodata")
        if not file_commands:
            continue
        for command in file_commands:
            text = re.sub("0x[0-9a-zA-Z]{4,8}", '', command)
            commands.append(text)
        parsed_count += 1
        print(f"parsed: {parsed_count}/{safe_count}")

        try:
            files[filename] = {
                "original_opcodes": " ".join(
                    [key for key, _group in groupby(commands)]) if commands else FAILED_TO_DISASSEMBLE,
                "processed_opcodes": " ".join([key for key, _group in groupby(commands)]) if commands else FAILED_TO_DISASSEMBLE,
                "virus": 'not a virus'
            }
        except Exception as e:
            print(filename)
            raise e

    df = pd.DataFrame.from_dict(data=files, columns=[OPCODES_COLUMN, 'virus'], orient="index")
    df.dropna(inplace=True)
    df.to_csv("safe2.csv")


change_labels(True)
