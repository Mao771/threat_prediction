from util.db_helper import DbHelper
import os
import pandas as pd


def display(data):
    data.time = pd.to_datetime(data.time).dt.strftime('%H:%M:%S')
    print(data.describe())


if __name__ == '__main__':
    conf = os.path.abspath('settings.conf')
    db_helper = DbHelper(conf)

    series = db_helper.get(measurements='snort_log',
                           aggregation='',
                           fields=('*',))

    display(series)
