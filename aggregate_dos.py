from scapy.all import rdpcap
from collections import defaultdict
import boto3
from datetime import datetime
import numpy as np

# Read the PCAP file

s3 = boto3.client("s3")
s3.download_file("pfsense-traffic", "traffic_1.pcap", "traffic_1.pcap")
pcap_file = "traffic_1.pcap"
packets = rdpcap(pcap_file)

# Aggregation dictionary
ip_aggregation = defaultdict(dict)


# Iterate through each packet
for pkt in packets:
    if 'IP' in pkt:
        dt = datetime.fromtimestamp(pkt.time).strftime("%H:%M")
        if pkt['IP'].src not in ip_aggregation[dt]:
            ip_aggregation[dt][pkt['IP'].src] = 1
        else:
            ip_aggregation[dt][pkt['IP'].src] += 1
        if pkt['IP'].dst not in ip_aggregation[dt]:
            ip_aggregation[dt][pkt['IP'].dst] = 1
        else:
            ip_aggregation[dt][pkt['IP'].dst] += 1
        # ip_aggregation[dt]["ips"].add(pkt['IP'].src)
        # ip_aggregation[dt]["ips"].add(pkt['IP'].dst)
        # ip_aggregation[dt]['sent'] += 1
        # ip_aggregation[dt]['received'] += 1

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd


# Display the results
coefs = []
for dt, ip in ip_aggregation.items():
    dt: datetime
    coefs.append({"date": dt, "coef": np.sum(list(ip.values())) / len(ip.keys())})
    print(dt, "", np.sum(list(ip.values())), len(ip.keys()), np.sum(list(ip.values())) / len(ip.keys()))



coefs_df = pd.DataFrame.from_records(coefs)
sns.relplot(data=coefs_df, x="date", y="coef", kind="line")
plt.show()
