from util import DbHelper
from definitions import SETTINGS_FILE

import pandas as pd


def get_threats(days: int = 365):
    db_helper = DbHelper(SETTINGS_FILE)

    df_attacks = db_helper.get(measurements='snort_log',
                               aggregation='WHERE time <= now() AND time >= now() - {}d'.format(days),
                               fields=('detail', 'type'))

    df_attacks.sort_values('time', inplace=True)

    df_attacks_pivot = df_attacks.pivot_table(
        index='time',
        columns='detail',
        aggfunc=lambda x: len(x.unique()))

    df_attacks_pivot.index = pd.to_datetime(df_attacks_pivot.index)
    df_attacks_pivot = df_attacks_pivot.resample('H').count()

    return df_attacks_pivot
