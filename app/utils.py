from util import DbHelper
from definitions import SETTINGS_FILE
from functools import reduce

import pandas as pd
import numpy as np


def _non_negative_difference(df, columns):
    for col in columns:
        df[col] = df[col].diff()
        mean_value = df[col].where(df[col] > 0).dropna().mean()
        df[col][df[col] < 0] = mean_value


def _to_datetime(*data_frames):
    for df in data_frames:
        df.time = pd.to_datetime(df.time).dt.strftime('%d-%m-%y %H:%M:%S')

def get_attacks_info():
    db_helper = DbHelper(SETTINGS_FILE)

    series_attacks = db_helper.get(measurements='snort_log',
                                   aggregation='',
                                   fields=('destination', 'severity', 'detail', 'ruleid', 'type'))

    series_attacks.time = pd.to_datetime(series_attacks.time).dt.strftime('%d.%m.%Y')
    series_attacks.drop(['destination', 'severity', 'ruleid'], inplace=True, axis=1)
    series_attacks.to_csv('series_attacks_raw.csv')

    series_attacks = series_attacks.reset_index().pivot_table(index='time', columns='detail', aggfunc='sum')
    series_attacks.to_csv('series_attacks.csv')
    # grouped = series_attacks.groupby(['time', 'type']).sum()

    # grouped.reindex()
    # print(grouped.drop(columns=['severity', 'destination', 'protocol']))

    # sns.relplot(x="time", y="attack_rate", col="align",
    #            size="coherence", style="choice",
    #             facet_kws=dict(sharex=False),
    #             kind="line", legend="full", data=series_attacks)


def get_preprocessed_data():
    db_helper = DbHelper(SETTINGS_FILE)

    series_net = db_helper.get(measurements='net',
                               aggregation='WHERE interface=\'em0\' ORDER BY time desc LIMIT 200',
                               fields=('packets_recv as pr',
                                       'packets_sent as ps',
                                       'bytes_recv as br',
                                       'bytes_sent as bs'))

    processed_df = series_net.sort_values(by='time')
    processed_df.reset_index(drop=True, inplace=True)

    _non_negative_difference(processed_df, ('pr', 'ps', 'br', 'bs'))
    # processed_df.pr = processed_df.pr.diff()
    # processed_df.ps = processed_df.ps.diff()
    # processed_df.br = processed_df.br.diff()
    # processed_df.bs = processed_df.bs.diff()
    processed_df.dropna(inplace=True)
    return processed_df
    #cumulative_average = processed_df.pr.expanding(2).mean()


def create_dataset():
    db_helper = DbHelper(SETTINGS_FILE)

    series_net = db_helper.get(measurements='net',
                               aggregation='WHERE interface=\'em0\'',
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
                                   fields=('destination', 'severity', 'detail', 'ruleid', 'type'))

    _to_datetime(series_net, series_cpu, series_mem, series_attacks)
    _non_negative_difference(series_net, 'packets_recv',
                             'packets_sent',
                             'bytes_recv',
                             'bytes_sent')

    dfs = [series_net, series_cpu, series_mem, series_attacks]
    df_final = reduce(lambda left, right: pd.merge(left, right, on='time', how='left'), dfs)
    df_final['mark'] = np.where(pd.isna(df_final.type), 'normal', 'attack')
    df_final.packets_recv.dropna()

    return df_final
