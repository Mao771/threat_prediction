from util import DbHelper
from definitions import SETTINGS_FILE
from functools import reduce
from random import random

import numpy as np
import pandas as pd

db_helper = DbHelper(SETTINGS_FILE)


def get_threats(days: int = 365):
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


def get_traffic_threats(interface: str = 'em0',
                        target_column: str = 'type',
                        reduce_classes=False):
    series_net = db_helper.get(measurements='net',
                               aggregation="WHERE interface='{}'".format(interface),
                               fields=('packets_recv',
                                       'packets_sent',
                                       'bytes_recv',
                                       'bytes_sent',
                                       'drop_in',
                                       'drop_out',
                                       'err_in',
                                       'err_out'))

    series_cpu = db_helper.get(measurements='cpu',
                               aggregation='WHERE cpu=\'cpu-total\'',
                               fields=('usage_system', 'usage_user'))

    series_mem = db_helper.get(measurements='mem',
                               aggregation='',
                               fields=('used_percent', 'buffered', 'cached'))

    series_attacks = db_helper.get(measurements='snort_log',
                                   aggregation='',
                                   fields=('detail', 'type'))

    to_datetime(series_net, series_cpu, series_mem, series_attacks)
    non_negative_difference(series_net, 'packets_recv',
                            'packets_sent',
                            'bytes_recv',
                            'bytes_sent')

    dfs = [series_net, series_cpu, series_mem, series_attacks]
    df_final = reduce(lambda left, right: pd.merge(left, right, on='time', how='left'), dfs)

    if reduce_classes:
        df_final[target_column] = np.where(pd.isna(df_final[target_column]), 'normal', 'attack')
    else:
        df_final[target_column] = df_final[target_column].fillna(value='normal')

    return df_final


def to_datetime(*data_frames):
    for df in data_frames:
        df.time = pd.to_datetime(df.time).dt.strftime('%d-%m-%y %H:%M:%S')


def non_negative_difference(df, *columns):
    for col in columns:
        df[col] = df[col].diff()
        mean_value = df[col].where(df[col] > 0).dropna().mean()
        df[col][df[col].isna()] = df[col][df[col] < 0] = mean_value


def replace_na(df, *columns):
    for col in columns:
        mean_val = df[col].dropna().mean()
        df[col][df[col].isna()] = df[col][df[col].isna()].apply(lambda x: mean_val * (random() / 3 + 0.7))
