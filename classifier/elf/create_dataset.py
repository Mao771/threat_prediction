import requests
from tqdm import tqdm
from requests.adapters import HTTPAdapter, Retry
import json
import os
import signal

retries = Retry(
    total=5,
    backoff_factor=1
)
s = requests.Session()
s.mount("https://", HTTPAdapter(max_retries=retries))

fname = "virustotal_elf/virustotal_elf.json"

os.makedirs("virustotal_elf", exist_ok=True)
os.makedirs("elf_detailed", exist_ok=True)

try:
    with open(fname, "r") as f:
        virus_analysis = json.load(f)
except FileNotFoundError:
    virus_analysis = {}


def handler(signum, frame):
    print("KILLING")
    with open(fname, "w+") as f:
        json.dump(virus_analysis, f)


def get_viruses():
    with open("virus_analysis_extended.json") as f:
        vae = json.load(f)

    hashes = list(vae.keys())

    new_files = os.listdir("/home/max/Downloads/VirusShare_ELF_20190212")
    new_hashes = [f.split("_")[1] for f in new_files]

    return set(new_hashes).difference(set(hashes))


signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGILL, handler)
print(len(virus_analysis.keys()))

with open("../../vt_tokens.json", "r") as vt_tokens_f:
    vt_tokens = json.load(vt_tokens_f)

vt_tokens_index = 0
viruses = get_viruses()

with tqdm(total=len(viruses)) as progress:
    for file in viruses:
        file_name = file
        if file_name in virus_analysis:
            print(f"Found {file_name}")
            continue
        response = s.get(f"https://www.virustotal.com/api/v3/files/{file_name}",
                         headers={'x-apikey': vt_tokens[vt_tokens_index]})
        response_json = response.json()
        try:
            virus_analysis[file_name] = response_json["data"]["attributes"]["last_analysis_results"]
            with open(f"elf_detailed/virus_analysis_%s.json" % file_name, "w+") as f:
                json.dump(response_json, f)
        except KeyError:
            print(response_json)
            with open(fname, "w+") as f:
                json.dump(virus_analysis, f)
            print(len(virus_analysis.keys()))
            vt_tokens_index += 1
            if len(vt_tokens) == vt_tokens_index:
                print("EXITING!")
                exit(0)
        print(len(virus_analysis.keys()))
        progress.update()

print("Writing virus analysis file started")
with open(fname, "w+") as f:
    json.dump(virus_analysis, f)
print("Writing virus analysis file finished")
print(len(virus_analysis.keys()))
