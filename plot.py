import matplotlib.pyplot as plt
from util import DbHelper
import os
import threading
import pandas as pd


def update_info():
    plt.clf()
    threading.Timer(10.0, update_info).start()

    series = db_helper.get(measurements='net',
                           aggregation='WHERE interface=\'em0\' ORDER BY time desc LIMIT 7',
                           fields=('-1*difference(packets_recv) as pr',))
    fig, ax = plt.subplots()
    ax.plot(pd.to_datetime(series.time).apply(lambda x: x.strftime("%H:%M:%S")), series.pr, marker="o")
    ax.set_ylabel("packets_recv")
    plt.show()


if __name__=='__main__':
    conf = os.path.abspath('settings.conf')
    db_helper = DbHelper(conf)

    update_info()
