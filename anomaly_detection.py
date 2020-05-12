from util import DbHelper, get_preprocessed_traffic
from detection import EWMADetector, ChaosDetector
from definitions import SETTINGS_FILE

import warnings
warnings.filterwarnings("ignore")

results_points = []


def append_point(time, detail, type='Traffic anomaly'):
    results_points.append({
        "measurement": "snort_log",
        "time": time,
        "fields": {
            "detail": detail,
            "protocol": "N/A",
            "ruleid": "N/A",
            "listid": "N/A"
        },
        "tags": {
            "source": "N/A",
            "destination": "N/A",
            "host": "N/A",
            "severity": "N/A",
            "path": "N/A",
            "type": type,
            "value": "N/A"
        }
    })


if __name__ == '__main__':
    db_helper = DbHelper(SETTINGS_FILE)

    data = get_preprocessed_traffic(minutes=60)

    ewma_detector = EWMADetector(data)
    chaos_detector = ChaosDetector(data)

    anomalies_ewma = ewma_detector.detect(plot=False)
    anomalies_chaos = chaos_detector.detect()

    ewma_anomalies_time = [time for time in anomalies_ewma.index]
    chaos_anomalies_time = [time for time in anomalies_chaos.index]

    for time in ewma_anomalies_time:
        append_point(time, 'EWMA Detected Traffic Anomaly')
    for time in chaos_anomalies_time:
        append_point(time, 'Chaos Detected Traffic Anomaly')

    db_helper.write(results_points)
