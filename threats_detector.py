from util import DbHelper, get_preprocessed_traffic
from detection import EWMADetector, ChaosDetector
from definitions import SETTINGS_FILE

import warnings
import sys
warnings.filterwarnings("ignore")

results_points = []


def append_point(time, detail, type='Traffic anomaly'):
    results_points.append({
        "measurement": "snort_log",
        "time": time,
        "fields": {
            "detail": detail,
            "protocol": "TEST",
            "ruleid": "N/A",
            "listid": "N/A"
        },
        "tags": {
            "source": "TEST",
            "destination": "TEST",
            "host": "TEST",
            "severity": "TEST",
            "path": "N/A",
            "type": type,
            "value": "N/A"
        }
    })


if __name__ == '__main__':
    db_helper = DbHelper(SETTINGS_FILE)
    args = dict(arg.split('=') for arg in sys.argv[1:])
    try:
        minutes = 20#int(args['minutes'])
    except:
        print('Pass the parameter for detection horizon in minutes, for example: python threats_detector.py minutes=20')
    else:
        print('Detecting anomalies for {0} minutes horizon'.format(minutes))

        data = get_preprocessed_traffic(minutes=200, from_begin=False)
        # data = data.pr[30:]

        ewma_detector = EWMADetector(data)
        chaos_detector = ChaosDetector(data)

        print("Detecting using EWMADetector...")
        anomalies_ewma = ewma_detector.detect(plot=False)
        print("Detecting using ChaosDetector...")
        anomalies_chaos = chaos_detector.detect()

        print(f'EWMA anomalies detected count is {len(anomalies_ewma.index)}')
        print(f'Chaos anomalies detected count is {len(anomalies_chaos.index)}')

        ewma_anomalies_time = [time for time in anomalies_ewma.index]
        chaos_anomalies_time = [time for time in anomalies_chaos.index]

        for time in ewma_anomalies_time:
            append_point(time, 'EWMA Detected Traffic Anomaly')
        for time in chaos_anomalies_time:
            append_point(time, 'Chaos Detected Traffic Anomaly')

        print("Writing results to the database")
        db_helper.write(results_points)
