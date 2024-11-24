from statsmodels.tsa.arima.model import ARIMA
import math
from sklearn.metrics import mean_squared_error, r2_score
import matplotlib
from matplotlib import pyplot
import pandas as pd
import numpy as np
from statsmodels.tsa.api import SimpleExpSmoothing, ExponentialSmoothing, ETSModel
from scipy.optimize import minimize
from sklearn.model_selection import train_test_split

matplotlib.use('TkAgg')


class ChaosDetector:

    def __init__(self, traffic_data: pd.DataFrame, arima_order=(1, 1, 0)):
        self.traffic_data = traffic_data
        self.arima_order = arima_order

    def detect(self):
        X = self.traffic_data.pr

        train_size = int(len(X) * 0.66)
        train, test = X[0:train_size], X[train_size:]

        self.forecast_arima(train, test, self.arima_order)

    def forecast_arima(self, train, test, arima_order=(5, 1, 0), log=False):
        history = [x for x in train]
        predictions = list()
        lp_scores = list()

        zero_pred_error = 1
        index = 0

        for idx, t in test.items():
            model = ARIMA(history, order=arima_order)
            model_fit = model.fit()
            output = model_fit.forecast()
            yhat = output[0]
            predictions.append(yhat)
            obs = t

            if index == 0:
                zero_pred_error = obs - yhat
            else:
                try:
                    lp_scores.append({'index': idx,
                                      'val': (math.log(abs((obs - yhat) / zero_pred_error))) / index})
                except ValueError:
                    lp_scores.append(0)

            history.append(obs)
            index += 1

            if log:
                print('predicted=%f, expected=%f' % (yhat, obs))
        error = mean_squared_error(test, predictions)
        indexes = [lp_score['index'] for lp_score in lp_scores if lp_score['val'] > 0]
        anomaly_traffic = self.traffic_data.iloc[indexes, :]

        if log:
            print('Test MSE: %.3f' % error)
            pyplot.plot(test)
            pyplot.plot(predictions, color='red')
            pyplot.show()

            pyplot.plot(lp_scores)
            pyplot.show()

        return anomaly_traffic

    def _forecast(self, train, test, arima_order=(1, 1, 0), log=False):
        model = ARIMA(train, order=arima_order)
        model = model.fit()
        predictions = model.forecast(steps=len(test))

        lp_scores = list()
        zero_pred_error = 1
        index = 0
        predictions = list()
        history = train.copy()

        for idx, t in test.items():

            model = ARIMA(history, order=arima_order)
            model_fit = model.fit()
            output = model_fit.forecast()
            yhat = output.values[0]
            predictions.append(yhat)
            obs = t

            if index == 0:
                zero_pred_error = obs - yhat
            else:
                try:
                    lp_scores.append({'index': idx,
                                      'val': (math.log(abs((obs - yhat) / zero_pred_error))) / index})
                except ValueError:
                    lp_scores.append(0)

            np.append(history, obs)
            index += 1

            if log:
                print('predicted=%f, expected=%f' % (yhat, obs))

        # lp_scores = []
        lp_scores_variance = []
        mean = np.mean(test.values)
        for index, obs_pred in enumerate(zip(test.values, predictions)):
            if index == 0:
                zero_pred_error = obs_pred[0] - obs_pred[1]
            else:
                # lp_scores.append({
                #     'index': index,
                #     'val': math.log(2 * abs(obs_pred[0] - obs_pred[1])) / index
                # })
                lp_scores_variance.append({
                    'index': index,
                    'val': math.log(2 * abs(test.values[index] - mean)) / index
                })

        # error = mean_squared_error(test, predictions)
        indexes = [lp_score['index'] for lp_score in lp_scores_variance if lp_score['val'] > 0]
        anomaly_traffic = self.traffic_data.loc[indexes, :]
        if log:
            # print('Test MSE: %.3f' % error)
            # pyplot.plot(test)
            # pyplot.plot(predictions, color='red')
            # pyplot.show()

            pyplot.plot([lp["index"] for lp in lp_scores], [lp["val"] for lp in lp_scores])
            pyplot.show()

            pyplot.plot([lp["index"] for lp in lp_scores_variance], [lp["val"] for lp in lp_scores_variance])
            pyplot.show()

        return anomaly_traffic

    def detect_mse(self):
        lp_scores_variance = []
        mean = np.mean(self.traffic_data)
        for index, value in enumerate(self.traffic_data.pr.values):
            lp_scores_variance.append({
                'index': index,
                'val': math.log(2 * abs(value - mean))
            })

        indexes = [lp_score['index'] for lp_score in lp_scores_variance if lp_score['val'] < 0]
        anomaly_traffic = self.traffic_data.loc[indexes, :]
        return anomaly_traffic

    def detect_with_dates(self):
        X = self.traffic_data.pr

        train_size = int(len(X) * 0.66)
        train, test = X[0:train_size], X[train_size:]

        return self._forecast(train, test, self.arima_order)

    def detect_r_sq(self):
        lp_scores = [{'index': i, 'val': math.log(abs(1 - 2*x)) / (i + 1)} for i, x in enumerate(self.traffic_data.pr)]
        pyplot.plot([lp["index"] for lp in lp_scores], [lp["val"] for lp in lp_scores])
        pyplot.show()

    def detect_l_sq(self, log=True):
        X = np.array(self.traffic_data.pr)
        y = np.array(self.traffic_data.coef)

        train_size = int(len(X) * 0.2)
        train, test = X[0:train_size], X[train_size:]
        y_train, y_test = y[0:train_size], y[train_size:]

        lp_scores = []

        for i, t in enumerate(test):
            A = np.stack([train, np.ones(len(train))]).T

            m, c = np.linalg.lstsq(A, y_train, rcond=None)[0]
            if m == 0:
                print(self.traffic_data.index[train_size + i], "", 0)

                lp_scores.append({
                    'index': i,
                    'val': 0
                })
                train = np.append(train, t)
                y_train = np.append(y_train, y_test[i])
                continue

            lp_val = math.log(abs(m))
            lp_scores.append({
                'index': i,
                'val': lp_val
            })

            train = np.append(train, t)
            y_train = np.append(y_train, y_test[i])

            print(self.traffic_data.index[train_size + i], "", lp_val, "", m)

        indexes = [train_size + 1 + lp_score['index'] for lp_score in lp_scores if lp_score['val'] > 0]
        anomaly_traffic = self.traffic_data.iloc[indexes, :]

        if log:
            pyplot.plot([lp["index"] for lp in lp_scores], [lp["val"] for lp in lp_scores])
            pyplot.show()

        return anomaly_traffic

    def detect_poly_reg(self, coefs, log=False):
        X = np.array(self.traffic_data.pr)
        y = np.array(self.traffic_data.coef)

        train_size = int(len(X) * 0.2)
        train, test = X[0:train_size], X[train_size:]
        y_train, y_test = y[0:train_size], y[train_size:]

        lp_scores = []
        coef = coefs[1]

        for i, t in enumerate(test):
            lp_val = math.log(abs(coef))
            lp_scores.append({
                'index': i,
                'val': lp_val
            })

            train = np.append(train, t)
            y_train = np.append(y_train, y_test[i])

            result = np.polyfit(train, y_train, 3)
            coef = 3 * result[1]
            x = train[i]
            y = (result[0] * (x ** 3)) + (result[1] * (x ** 2)) + (result[2] * x) + result[3]

            print(self.traffic_data.index[train_size + i], "", t, "", lp_val, "", coef, "", y, "", math.log(abs(y - t)))

        indexes = [train_size + 1 + lp_score['index'] for lp_score in lp_scores if lp_score['val'] > 0]
        anomaly_traffic = self.traffic_data.iloc[indexes, :]

        if log:
            pyplot.plot([lp["index"] for lp in lp_scores], [lp["val"] for lp in lp_scores])
            pyplot.show()

        return anomaly_traffic

    def detect_ewma(self, log=True):
        alpha=0.3
        X = self.traffic_data.pr.ewm(alpha=alpha, adjust=False).mean()
        x_shifted = X.shift(periods=1)

        X = np.array(X)
        x_shifted = np.array(x_shifted)
        lp_scores = []

        for i, t in enumerate(X):
            if i == 0:
                continue

            lp_val = math.log(abs(t - x_shifted[i]))
            lp_scores.append({
                'index': i,
                'val': lp_val
            })

            print(self.traffic_data.index[i], "", lp_val)

        indexes = [lp_score['index'] for lp_score in lp_scores if lp_score['val'] > 0]
        anomaly_traffic = self.traffic_data.iloc[indexes, :]

        if log:
            pyplot.plot([lp["index"] for lp in lp_scores], [lp["val"] for lp in lp_scores])
            pyplot.show()

        return anomaly_traffic

    def mse(self, alpha, data):
        model = SimpleExpSmoothing(data).fit(smoothing_level=alpha, optimized=False)
        predictions = model.fittedvalues
        return np.mean((np.array(data) - predictions) ** 2)

    # Optimize alpha
    def optimize_alpha(self, data):
        result = minimize(
            lambda alpha: self.mse(alpha, data),
            x0=0.5,  # Initial guess for alpha
            bounds=[(0, 1)],  # Alpha must be between 0 and 1
            method='L-BFGS-B'  # Optimization method
        )
        return result.x[0]

    def detect_ses(self, log=True):
        train_x, test_x = train_test_split(self.traffic_data.pr, test_size=0.01)

        # Get the optimal alpha
        optimal_alpha = self.optimize_alpha(train_x)

        lp_scores = []
        for i, t in enumerate(test_x):
            model = ETSModel(train_x)
            model = model.fit()
            forecasts = model.forecast()
            err = mean_squared_error([t], forecasts)

            lp_val = math.log(abs(err))
            lp_scores.append({
                'index': i,
                'val': lp_val
            })

            print(self.traffic_data.index[i], "", lp_val)
            train_x = np.append(train_x, t)

        indexes = [lp_score['index'] for lp_score in lp_scores if lp_score['val'] > 0]
        anomaly_traffic = self.traffic_data.iloc[indexes, :]

        if log:
            pyplot.plot([lp["index"] for lp in lp_scores], [lp["val"] for lp in lp_scores])
            pyplot.show()

        return anomaly_traffic
