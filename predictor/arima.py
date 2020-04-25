from util import DbHelper
from definitions import ROOT_DIR
import os
from sklearn.metrics import mean_squared_error
from pandas import DataFrame
from matplotlib import pyplot
from statsmodels.graphics.tsaplots import plot_pacf, plot_acf
from statsmodels.tsa.seasonal import seasonal_decompose
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima_model import ARIMA
from pandas.plotting import autocorrelation_plot
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings("ignore")


def display(data):
    data.time = pd.to_datetime(data.time).dt.strftime('%H:%M:%S')
    data.plot()
    pyplot.show()


def fit(data, order=(1, 1, 1)):
    data_log = np.log(data)
    #decomposition = seasonal_decompose(data_log)

    model = ARIMA(data_log, order)
    model_fit = model.fit(disp=-1)
    print(model_fit.summary())

    residuals = DataFrame(model_fit.resid)
    residuals.plot()
    pyplot.show()
    residuals.plot(kind='kde')
    pyplot.show()
    print(residuals.describe())

    make_stationary_time_shift(data).plot()
    pyplot.plot(model_fit.fittedvalues, color='red')
    pyplot.show()


def forecast(train, test, arima_order=(5, 1, 0), log=False):
    history = [x for x in train]
    predictions = list()
    for t in range(len(test)):
        model = ARIMA(history, order=arima_order)
        model_fit = model.fit(disp=0)
        output = model_fit.forecast()
        yhat = output[0]
        predictions.append(yhat)
        obs = test[t]
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


def calculate_cvss_metric():
    pass


def get_stationarity(data_frame):
    rolling = data_frame.rolling(window=11)

    rolling_mean = rolling.mean()
    rolling_std = rolling.std()

    pyplot.plot(data_frame, color='blue', label='Original')
    pyplot.plot(rolling_mean, color='red', label='Rolling Mean')
    pyplot.plot(rolling_std, color='black', label='Rolling Standard')

    pyplot.legend(loc='best')

    pyplot.title('Rolling Mean & Rolling Standard Deviation packets received')
    pyplot.show()

    adf, pvalue, _, _, critical_values, _ = adfuller(data_frame)

    print('ADF statistic: {}\np-value: {}\n'.format(adf, pvalue))
    print('Critical values:')
    for key, value in critical_values.items():
        print('\t{}: {}'.format(key, value))

    return data_frame


def make_stationary(data_frame):
    roll_mean = data_frame.rolling(window=12).mean()

    df_minus_mean = data_frame - roll_mean
    df_minus_mean.dropna(inplace=True)

    return get_stationarity(df_minus_mean)


def make_stationary_ewm(data_frame):
    df_log = np.log(data_frame)
    roll_mean_ewm = df_log.ewm(halflife=12, min_periods=0,
                                       adjust=True).mean()
    df_log_exp_decay = df_log - roll_mean_ewm
    df_log_exp_decay.dropna(inplace=True)

    return get_stationarity(df_log_exp_decay)


def make_stationary_time_shift(data_frame):
    df_log = np.log(data_frame)

    df_log_shift = df_log - df_log.shift()
    df_log_shift.dropna(inplace=True)

    return get_stationarity(df_log_shift)


if __name__ == '__main__':
    conf = os.path.join(ROOT_DIR, 'settings.conf')
    db_helper = DbHelper(conf)

    series_net = db_helper.get(measurements='net',
                               aggregation='WHERE interface=\'em0\' LIMIT 50',
                               fields=('non_negative_difference(packets_recv) as pr',
                                       'non_negative_difference(packets_sent) as ps',
                                       'non_negative_difference(bytes_recv) as br',
                                       'non_negative_difference(bytes_sent) as bs'))

    # make_stationary(series_net.pr)
    # make_stationary_ewm(series_net.pr)
    # make_stationary_time_shift(series_net.pr)

    # autocorrelation_plot(series_net.pr)
    # pyplot.show()
    # # p = ?
    # plot_pacf(series_net.pr, lags=100)
    # pyplot.show()
    # # q = 2
    # plot_acf(series_net.pr, lags=100)
    # pyplot.show()
    # # d = 4

    fit(series_net.pr)

    # df_log = np.log(series_net.pr)
    # pyplot.plot(df_log)
    # pyplot.show()
