from statsmodels.tsa.arima.model import ARIMA
import math
from sklearn.metrics import mean_squared_error
from matplotlib import pyplot
import pandas as pd
import numpy as np



class ChaosDetector:

    def __init__(self, traffic_data: pd.DataFrame, arima_order=(1, 1, 0)):
        self.traffic_data = traffic_data
        self.arima_order = arima_order

    def detect(self):
        X = self.traffic_data.pr

        train_size = int(len(X) * 0.66)
        train, test = X[0:train_size], X[train_size:]

        return self._forecast(train, test, self.arima_order)

    def _forecast(self, train, test, arima_order=(1, 1, 0), log=True):
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
        # indexes = [lp_score['index'] for lp_score in lp_scores if lp_score['val'] < 0]
        # anomaly_traffic = self.traffic_data.loc[indexes, :]
        anomaly_traffic = []
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

    def detect_with_dates(self):
        X = self.traffic_data.pr

        train_size = int(len(X) * 0.66)
        train, test = X[0:train_size], X[train_size:]

        return self._forecast(train, test, self.arima_order)
