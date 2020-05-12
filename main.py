from util import get_preprocessed_traffic
from detection import EWMADetector, ChaosDetector
import datetime
import warnings
warnings.filterwarnings("ignore")


if __name__ == '__main__':
    results_ewma = {}
    results_chaos = {}

    for minutes in range(10, 70, 10):
        data = get_preprocessed_traffic(minutes=minutes)

        ewma_detector = EWMADetector(data)
        chaos_detector = ChaosDetector(data)

        start_ewma = datetime.datetime.now()
        anomalies_ewma = ewma_detector.detect(plot=False)
        stop_ewma = datetime.datetime.now()
        results_ewma[minutes] = {
            'time': (stop_ewma - start_ewma).microseconds * 1000,
            'anomalies': len(anomalies_ewma.index)
        }

        start_chaos = datetime.datetime.now()
        anomalies_chaos = chaos_detector.detect()
        stop_chaos = datetime.datetime.now()
        results_chaos[minutes] = {
            'time': (stop_chaos - start_chaos).microseconds * 1000,
            'anomalies': len(anomalies_chaos.index)
        }
        print(f"Iter minutes {minutes}\n")

    print(f"\n====EWMADetector results====\n")
    for key, value in results_ewma.items():
        print(f"{key} minutes period:\n{value['time']}s {value['anomalies']} anomalies\n")
    print(f"\n====ChaosDetector results====\n")
    for key, value in results_chaos.items():
        print(f"{key} minutes period:\n{value['time']}s {value['anomalies']} anomalies\n")
