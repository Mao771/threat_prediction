from statsmodels.tsa.stattools import adfuller
from pandas.plotting import autocorrelation_plot
from statsmodels.graphics.tsaplots import acf

import pandas as pd


def check_adfuller(series: pd.Series, verbose: bool = True):
    result = adfuller(series)

    if verbose:
        print('ADF Statistic: %f' % result[0])
        print('p-value: %f' % result[1])
        print('Critical Values:')
        for key, value in result[4].items():
            print('\t%s: %.3f' % (key, value))

    return result[1] < 0.05


def check_autocorrelation(series: pd.Series,
                          show_plot: bool = False):
    if show_plot:
        autocorrelation_plot(series)

    return acf(series)


    # def get_stationarity(data_frame):
    #     rolling = data_frame.rolling(window=11)
    #
    #     rolling_mean = rolling.mean()
    #     rolling_std = rolling.std()
    #
    #     pyplot.plot(data_frame, color='blue', label='Original')
    #     pyplot.plot(rolling_mean, color='red', label='Rolling Mean')
    #     pyplot.plot(rolling_std, color='black', label='Rolling Standard')
    #
    #     pyplot.legend(loc='best')
    #
    #     pyplot.title('Rolling Mean & Rolling Standard Deviation packets received')
    #     pyplot.show()
    #
    #     adf, pvalue, _, _, critical_values, _ = adfuller(data_frame)
    #
    #     print('ADF statistic: {}\np-value: {}\n'.format(adf, pvalue))
    #     print('Critical values:')
    #     for key, value in critical_values.items():
    #         print('\t{}: {}'.format(key, value))
    #
    #     return data_frame
    #
    #
    # def make_stationary(data_frame):
    #     roll_mean = data_frame.rolling(window=12).mean()
    #
    #     df_minus_mean = data_frame - roll_mean
    #     df_minus_mean.dropna(inplace=True)
    #
    #     return get_stationarity(df_minus_mean)
    #
    #
    # def make_stationary_ewm(data_frame):
    #     df_log = np.log(data_frame)
    #     roll_mean_ewm = df_log.ewm(halflife=12, min_periods=0,
    #                                adjust=True).mean()
    #     df_log_exp_decay = df_log - roll_mean_ewm
    #     df_log_exp_decay.dropna(inplace=True)
    #
    #     return get_stationarity(df_log_exp_decay)
    #
    #
    # def make_stationary_time_shift(data_frame):
    #     df_log = np.log(data_frame)
    #
    #     df_log_shift = df_log - df_log.shift()
    #     df_log_shift.dropna(inplace=True)
    #
    #     return get_stationarity(df_log_shift)

    # def fit(data, order=(1, 1, 1)):
    #     data_log = np.log(data)
    #     #decomposition = seasonal_decompose(data_log)
    #
    #     model = ARIMA(data_log, order)
    #     model_fit = model.fit(disp=-1)
    #     print(model_fit)
    #
    #     residuals = DataFrame(model_fit.resid)
    #     residuals.plot()
    #     pyplot.show()
    #     residuals.plot(kind='kde')
    #     pyplot.show()
    #     print(residuals.describe())
    #
    #     make_stationary_time_shift(data).plot()
    #     pyplot.plot(model_fit.fittedvalues, color='red')
    #     pyplot.show()

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
    # df_log = np.log(series_net.pr)
    # pyplot.plot(df_log)
    # pyplot.show()