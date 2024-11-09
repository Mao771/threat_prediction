from scapy.all import rdpcap
from collections import defaultdict
import boto3
from datetime import datetime, timedelta
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from util import DbHelper
from definitions import SETTINGS_FILE
from detection import EWMADetector
import math
from time import sleep

import matplotlib
matplotlib.use('TkAgg')


# Read the PCAP file
def get_traffic_from_s3(pcap_file_local, file_name, db_helper, plot=True):
    packets = rdpcap(pcap_file_local)
    # Aggregation dictionary
    ip_aggregation = defaultdict(dict)
    # Iterate through each packet
    for pkt in packets:
        if 'IP' in pkt:
            dt = datetime.fromtimestamp(float(pkt.time))
            if dt.second >= 55:
                dt = (dt + timedelta(seconds=5)).strftime("%d-%m-%Y.%H:%M:%S")
            else:
                dt = dt.replace(second=round(int(dt.second), -1)).strftime("%d-%m-%Y.%H:%M:%S")
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

    # Display the results
    coefs = []
    for dt, ip in ip_aggregation.items():
        dt: datetime
        coefs.append({"date": dt, "coef": np.sum(list(ip.values())) / len(ip.keys())})
        # print(dt, "", np.sum(list(ip.values())), len(ip.keys()), np.sum(list(ip.values())) / len(ip.keys()))

    save_coefs_to_influx(db_helper, coefs, 'ip_packet_coef_10s_new')

    if plot:
        coefs_df = pd.DataFrame.from_records(coefs)
        sns.relplot(data=coefs_df, x="date", y="coef", kind="line")
        plt.show()


def aggregate_syn_ack(file_name, db_helper, plot=True):
    s3 = boto3.client("s3")
    pcap_file_local = "traffic.pcap"
    s3.download_file("pfsense-traffic", file_name, pcap_file_local)
    packets = rdpcap(pcap_file_local)
    ip_aggregation = defaultdict(dict)
    for pkt in packets:
        dt = datetime.fromtimestamp(pkt.time).strftime("%H:%M")
        if dt not in ip_aggregation:
            ip_aggregation[dt] = {
                'syn': 0,
                'all': 0
            }
        if 'TCP' in pkt:
            if pkt['TCP'].flags == 'S':
                ip_aggregation[dt]['syn'] += 1
        ip_aggregation[dt]['all'] += 1

    coefs = []
    for dt, ip in ip_aggregation.items():
        dt: datetime
        coefs.append({"date": dt, "coef": ip['syn'] / ip['all']})
        print(dt, "", ip['syn'] / ip['all'])

    save_coefs_to_influx(db_helper, coefs, 'syn_coef')

    if plot:
        coefs_df = pd.DataFrame.from_records(coefs)
        sns.relplot(data=coefs_df, x="date", y="coef", kind="line")
        plt.show()


def save_coefs_to_influx(db_helper: DbHelper, coefs: list, measurement: str = 'ip_packet_coef'):
    db_data = [{
        'measurement': measurement,
        'fields': {
            "dt": coef["date"],
            "coef": coef["coef"]
        }
    } for coef in coefs]
    db_helper.write(db_data)


def plot_total_coefs(db_helper: DbHelper):
    data = db_helper.get('ip_packet_coef_10s_new', "", "*")
    print(data)

    sns.relplot(data=data, x="dt", y="coef", kind="line")
    plt.show()
    ewma = EWMADetector(data)
    anomaly_traffic = ewma.detect(traffic_parameter="coef", traffic_parameter_name="Packets to address ratio")
    return anomaly_traffic


def fill_database():
    db_helper = DbHelper(SETTINGS_FILE)
    data = db_helper.get('ip_packet_coef', "", "*")

    start_hour = 14
    start_minute = 30

    dt = datetime(year=2024, month=10, day=19, hour=start_hour, minute=start_minute)

    while not (dt.hour == 19 and dt.minute == 39):
        f_name = f'traffc_{str(dt.hour).zfill(2)}{str(dt.minute).zfill(2)}'

        get_traffic_from_s3(f_name, db_helper, False)
        dt = dt + timedelta(minutes=1)

    print(plot_total_coefs(db_helper))


if __name__ == '__main__':
    db_helper = DbHelper(SETTINGS_FILE)
    data = db_helper.get('ip_packet_coef', "", "*")

    print("running ewma detection")
    while True:
        dt_now = datetime.utcnow()
        dt_hour = dt_now.hour
        dt_min = dt_now.minute
        dt_sec = round(dt_now.second / 10) * 10

        #f_name = f'traffc_{str(dt_hour).zfill(2)}{str(dt_min).zfill(2)}{str(dt_sec).zfill(2)}'
        f_name = "traffc"

        try:
            s3 = boto3.client("s3")
            pcap_file_local = "traffic.pcap"
            s3.download_file("pfsense-traffic", f_name, pcap_file_local)
        except Exception as e:
            continue
        try:
            get_traffic_from_s3(pcap_file_local, f_name, db_helper, False)
        except Exception as e:
            print(e)
            sleep(10)
            continue
        ewma = EWMADetector(data)
        anomaly_traffic = ewma.detect(traffic_parameter="coef", traffic_parameter_name="Packets to address ratio", plot=False)
        print("Anomalies:", anomaly_traffic)

        sleep(10)
