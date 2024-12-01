from util import DbHelper
from definitions import SETTINGS_FILE
from detection import EWMADetector
from time import sleep
from util import get_preprocessed_traffic

while True:
    db_helper = DbHelper(SETTINGS_FILE)
    data = get_preprocessed_traffic(minutes=50, from_begin=False)

    data['ps_pr_coef'] = data['ps'] / data['pr']

    ewma = EWMADetector(data)
    anomaly_traffic_ewma, anomaly_traffic_if = ewma.detect()
    print("Anomalies:", anomaly_traffic_ewma, "Anomalies IF:", anomaly_traffic_if)

    anomaly_traffic_ewma, anomaly_traffic_if = ewma.detect(traffic_parameter="ps_pr_coef", traffic_parameter_name="Packets sent/Packets received")
    print("Anomalies:", anomaly_traffic_ewma, "Anomalies IF:", anomaly_traffic_if)

    sleep(5)
