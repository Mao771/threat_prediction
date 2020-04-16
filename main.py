from util import DbHelper
import os
from sklearn.metrics import mean_squared_error
from pandas import DataFrame
from matplotlib import pyplot
from statsmodels.tsa.arima_model import ARIMA
from pandas.plotting import autocorrelation_plot
import pandas as pd
import warnings
import math
import numpy as np

from functools import reduce

warnings.filterwarnings("ignore")


def display(data):
    data.time = pd.to_datetime(data.time).dt.strftime('%H:%M:%S')
    data.plot()
    pyplot.show()


def fit(data):
    autocorrelation_plot(data)
    pyplot.show()

    model = ARIMA(data, order=(5, 1, 0))
    model_fit = model.fit(disp=0)
    print(model_fit.summary())

    residuals = DataFrame(model_fit.resid)
    residuals.plot()
    pyplot.show()
    residuals.plot(kind='kde')
    pyplot.show()
    print(residuals.describe())


def forecast(train, test, arima_order=(5, 1, 0), log=False):
    history = [x for x in train]
    predictions = list()
    lp_scores = list()

    zero_pred_error = 1

    for t in range(len(test)):

        model = ARIMA(history, order=arima_order)
        model_fit = model.fit(disp=0)
        output = model_fit.forecast()
        yhat = output[0]
        predictions.append(yhat)
        obs = test[t]

        if t == 0:
            zero_pred_error = obs - yhat
        else:
            try:
                lp_scores.append((math.log(abs((obs - yhat) / zero_pred_error)))/t)
            except ValueError:
                lp_scores.append(0)

        history.append(obs)

        if log:
            print('predicted=%f, expected=%f' % (yhat, obs))
    error = mean_squared_error(test, predictions)

    if log:
        print('Test MSE: %.3f' % error)
        # plot
        pyplot.plot(test)
        pyplot.plot(predictions, color='red')
        pyplot.show()


        pyplot.plot(lp_scores)
        pyplot.show()
    return error


# evaluate an ARIMA model for a given order (p,d,q)
def evaluate_arima_model(X, arima_order):
    # prepare training dataset
    train_size = int(len(X) * 0.66)
    train, test = X[0:train_size], X[train_size:]

    return forecast(train, test, arima_order=arima_order)

# evaluate combinations of p, d and q values for an ARIMA model
def evaluate_models(dataset, p_values, d_values, q_values):
    dataset = dataset.astype('float32')
    best_score, best_cfg = float("inf"), None
    for p in p_values:
        for d in d_values:
            for q in q_values:
                order = (p,d,q)
                try:
                    mse = evaluate_arima_model(dataset, order)
                    if mse < best_score:
                        best_score, best_cfg = mse, order
                    print('ARIMA%s MSE=%.3f' % (order,mse))
                except:
                    continue
    print('Best ARIMA%s MSE=%.3f' % (best_cfg, best_score))


def fib_number(n):
    if n in (1,2):
        return 1
    return fib_number(n-1) + fib_number(n-2)


def pow(n, i):
    if i == 0:
        return 1
    return n * pow(n, i - 1)


def get_attacks_info():
    conf = os.path.abspath('settings.conf')
    db_helper = DbHelper(conf)

    # series_snort = db_helper.get(measurements='snort_log',
    #                              aggregation='',
    #                              fields=('destination', 'severity', 'type', 'protocol'))

    series_attacks = db_helper.get(measurements='snort_log',
                                   aggregation='',
                                   fields=('destination', 'severity', 'detail', 'ruleid', 'type'))

    series_attacks.time = pd.to_datetime(series_attacks.time).dt.strftime('%d.%m.%Y')
    series_attacks.drop(['destination', 'severity', 'ruleid'], inplace=True, axis=1)
    series_attacks.to_csv('series_attacks_raw.csv')

    series_attacks = series_attacks.reset_index().pivot_table(index='time', columns='detail', aggfunc='sum')
    series_attacks.to_csv('series_attacks.csv')
    #grouped = series_attacks.groupby(['time', 'type']).sum()

    # grouped.reindex()
    # print(grouped.drop(columns=['severity', 'destination', 'protocol']))

    # sns.relplot(x="time", y="attack_rate", col="align",
    #            size="coherence", style="choice",
    #             facet_kws=dict(sharex=False),
    #             kind="line", legend="full", data=series_attacks)


def get_preprocessed_data():
    conf = os.path.abspath('settings.conf')
    db_helper = DbHelper(conf)

    series_net = db_helper.get(measurements='net',
                               aggregation='WHERE interface=\'em0\' ORDER BY time desc LIMIT 200',
                               fields=('packets_recv as pr',
                                       'packets_sent as ps',
                                       'bytes_recv as br',
                                       'bytes_sent as bs'))

    processed_df = series_net.sort_values(by='time')
    processed_df.reset_index(drop=True, inplace=True)

    non_negative_difference(processed_df, ('pr', 'ps', 'br', 'bs'))
    # processed_df.pr = processed_df.pr.diff()
    # processed_df.ps = processed_df.ps.diff()
    # processed_df.br = processed_df.br.diff()
    # processed_df.bs = processed_df.bs.diff()
    processed_df.dropna(inplace=True)
    return processed_df
    #cumulative_average = processed_df.pr.expanding(2).mean()


def non_negative_difference(df, *columns):
    for col in columns:
        df[col] = df[col].diff()
        mean_value = df[col].where(df[col] > 0).dropna().mean()
        df[col][df[col] < 0] = mean_value


def lyapunov_method():
    preprocessed_df = get_preprocessed_data()
    pyplot.plot(preprocessed_df.pr)
    pyplot.show()

    data = preprocessed_df.pr.values
    print(data)
    train_size = int(len(data) * 0.66)
    train, test = data[0:train_size], data[train_size:len(data)]
    forecast(train, test, log=True)


def create_dataset():
    conf = os.path.abspath('settings.conf')
    db_helper = DbHelper(conf)

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

    to_datetime(series_net, series_cpu, series_mem, series_attacks)
    non_negative_difference(series_net, 'packets_recv',
                            'packets_sent',
                            'bytes_recv',
                            'bytes_sent')

    dfs = [series_net, series_cpu, series_mem, series_attacks]
    df_final = reduce(lambda left, right: pd.merge(left, right, on='time', how='left'), dfs)
    df_final['mark'] = np.where(pd.isna(df_final.type), 'normal', 'attack')
    df_final.packets_recv.dropna()


def to_datetime(*data_frames):
    for df in data_frames:
        df.time = pd.to_datetime(df.time).dt.strftime('%d-%m-%y %H:%M:%S')


def replace_na(df, *columns):
    for col in columns:
        df[col][df[col].isna()] = df[col].dropna().mean()


if __name__ == '__main__':
    create_dataset()
    # 'non_negative_difference(packets_recv) as pr',
    # 'non_negative_difference(packets_sent) as ps',
    # 'non_negative_difference(bytes_recv) as br',
    # 'non_negative_difference(bytes_sent) as bs'

    # series_net.time=pd.to_datetime(series_net.time).dt.strftime('%d-%m-%y %H:%M:%S')
    # series_snort.time=pd.to_datetime(series_snort.time).dt.strftime('%d-%m-%y %H:%M:%S')
    #
    # result_series = pd.merge(series_net, series_snort, on='time', how='left')
    # result_series = result_series.drop_duplicates()
    # result_series['type'] = np.where(pd.isna(result_series.type), 'normal', 'attack')
    # result_series.to_csv('result.csv')
    # with pd.option_context('display.max_rows', None, 'display.max_columns', None):
    #     print(result_series)

    # print(fib_number(11))
    # print(pow(7, 5))
    # evaluate parameters
    # p_values = [0, 1, 2, 4, 6, 8, 10]
    # d_values = range(0, 3)
    # q_values = range(0, 3)

    # evaluate_models(series.pr.values, p_values, d_values, q_values)
