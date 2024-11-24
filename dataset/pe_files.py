import json
import os

import pandas as pd
from tqdm import tqdm
from sklearn.naive_bayes import MultinomialNB
import numpy as np
from parse_pe_file import parse_pe_imports

#
#
# df_virus = pd.read_csv('parsed_malware_pe_1.csv').dropna()
# df_virus = df_virus[df_virus['parsed']!='FAILED TO PARSE']
# df_not_virus = pd.read_csv('parsed_malware_pe_bening.csv').dropna()
# df_not_virus.loc[:, 'type'] = 'bening'
# df_not_virus = df_not_virus[df_not_virus['parsed']!='FAILED TO PARSE']
# df = pd.concat([df_virus, df_not_virus]).reset_index(drop=True)
#
# opcodes = [li for lis in [set(l.split(' ')) for l in df['parsed'].tolist()] for li in lis]
# opcodes_unique = list(set(opcodes))
#
# new_df = df['parsed'].str.split(" ", expand=True)# apply(lambda x: " ".join([str(opcodes_unique.index(opcode)) for opcode in x.split(' ')]))
# df.head()\

viruses = ["worm", "adware", "spy", "trojan"] # installcore


with open("/home/max/VirusShare/VirusShare_00486/virustotal_2024_pe/virustotal_2024_pe/virus_2024_pe.json") as f:
    vsh_2024 = json.load(f)

result = {}
for vf_hash, v in vsh_2024.items():
    path = f"/home/max/VirusShare/VirusShare_00486/VirusShare_{vf_hash}"
    vf_info = {"path": path, "imports": "", "type": ""}
    found = False
    for vir in viruses:
        for av, info in v.items():
            if info["result"] and info["result"].lower().find(vir) != -1:
                vf_info["type"] = vir
                found = True
                break
        if found:
            break
    vf_info["imports"] = parse_pe_imports(file_name=path)
    result[vf_hash] = vf_info

results_existing = pd.read_csv("vsh_result_virus_7").set_index("Unnamed: 0").to_dict(orient='index')
result_merged = {**result, **results_existing}
df = pd.DataFrame.from_dict(result_merged, orient='index')
print(df['type'].value_counts())
df.to_csv("vsh_result_virus_new")

dirs = [
    "VirusShare_00000",
    "VirusShare_Citadel-Zeus_PE-Arc_20130113-20130712",
    "VirusShare_InstallCore_000",
    "VirusShare_Mediyes_000",
    "VirusShare_x86-64_WinEXE_20130711",
    "VirusShare_Zeus_20190213",
]
for dir in dirs:
    full_path = f"/home/max/VirusShare/{dir}/manalyzer"
    print(full_path)
    for vf in os.listdir(full_path):
        vf_name = vf.split(".json")[0]
        vf_hash = vf_name.split("VirusShare_")[1]
        path = os.path.join(full_path, vf)
        try:
            with open(path) as f:
                vf_json = json.load(f)
                if len(vf_json.keys()) == 0:
                    continue
                vf_imports = vf_json[f"/root/torrent/{dir}/{vf_name}"]["Imports"]
                vf_info = {"path": path, "imports": "", "type": ""}
                if dir in ["VirusShare_InstallCore_000", "VirusShare_Zeus_20190213"]:
                    vf_info["imports"] = parse_pe_imports(file_name=os.path.join("/home/max", dir, vf_name))
                else:
                    for k, v in vf_imports.items():
                        vf_info["imports"] += f" {k}_".join(v)

                plugins_output = None
                found = False

                if vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]['level'] == 0:
                    vf_info["type"] = None
                else:
                    for v in viruses:
                        for v_scan in vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"].values():
                            if v_scan.lower().find(v) != -1:
                                vf_info["type"] = v
                                found = True
                                break
                        if found:
                            break

                #
                # if "BitDefender" in vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]:
                #     plugins_output = \
                #     vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]["BitDefender"]
                # elif "DrWeb" in vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]:
                #     plugins_output = \
                #     vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]["DrWeb"]
                # elif "ESET-NOD32" in vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]:
                #     plugins_output = \
                #     vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]["ESET-NOD32"]
                # elif "Zillya" in vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]:
                #     plugins_output = \
                #     vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]["Zillya"]
                # elif "Microsoft" in vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]:
                #     plugins_output = \
                #     vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"]["Microsoft"]
                # elif "McAfee-GW-Edition" in vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"][
                #     "plugin_output"]:
                #     plugins_output = \
                #     vf_json[f"/root/torrent/{dir}/{vf_name}"]["Plugins"]["virustotal"]["plugin_output"][
                #         "McAfee-GW-Edition"]
                # for vt in viruses:
                #     if plugins_output.lower().find(vt) != -1:
                #         vf_info["type"] = vt
                #         break

                if not vf_info["type"]:
                    print(vf_hash)
        except Exception as e:
            continue

        result[vf_hash] = vf_info

df = pd.DataFrame.from_dict(result, orient='index')
print(df['type'].value_counts())
df.to_csv("vsh_result_virus_7")
result = {}

# benign_res = {}
for bf in os.listdir("/home/max/DikeDataset/files/benign"):
    if bf.endswith('ole'):
        continue
    bf_hash = bf.split('.')[0]
    path = os.path.join('/home/max/DikeDataset/files/benign', bf)
    result[bf_hash] = {
        "path": path,
        "type": 'benign',
        'imports': parse_pe_imports(path)
    }


for bf in os.listdir("/home/max/vbox_shared"):
    if bf == 'dlls':
        continue
    if bf.endswith('ole'):
        continue
    path = os.path.join('/home/max/vbox_shared', bf)
    result[bf] = {
        'path': path,
        "type": 'benign',
        'imports': parse_pe_imports(path)
    }

for bf in os.listdir("/home/max/vbox_shared/dlls"):
    if bf.endswith('ole'):
        continue
    path = os.path.join('/home/max/vbox_shared/dlls', bf)
    result[bf] = {
        'path': path,
        "type": 'benign',
        'imports': parse_pe_imports(path)
    }
# pd.DataFrame.from_dict(benign_res, orient='index').to_csv("benign_result")

df = pd.DataFrame.from_dict(result, orient='index')
print(df['type'].value_counts())
df.to_csv("vsh_result_benign_7")
