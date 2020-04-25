from sklearn.metrics import mean_squared_error
from pandas import DataFrame
from matplotlib import pyplot
from statsmodels.tsa.arima_model import ARIMA
from pandas.plotting import autocorrelation_plot
import pandas as pd
import warnings
import math

from app.utils import get_preprocessed_data, create_dataset
from detection.EWMADetector import EWMADetector
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


def lyapunov_method():
    preprocessed_df = get_preprocessed_data()
    pyplot.plot(preprocessed_df.pr)
    pyplot.show()

    data = preprocessed_df.pr.values
    print(data)
    train_size = int(len(data) * 0.66)
    train, test = data[0:train_size], data[train_size:len(data)]
    forecast(train, test, log=True)


def replace_na(df, *columns):
    for col in columns:
        df[col][df[col].isna()] = df[col].dropna().mean()


if __name__ == '__main__':
    ds = create_dataset()
    ewma_detector = EWMADetector(ds.packets_recv)
    ewma_detector.detect()
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
