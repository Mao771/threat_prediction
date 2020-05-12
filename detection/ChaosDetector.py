from statsmodels.tsa.arima_model import ARIMA
import math
from sklearn.metrics import mean_squared_error
from matplotlib import pyplot
import pandas as pd

class ChaosDetector:

    def __init__(self, traffic_data: pd.DataFrame, arima_order=(5, 1, 0)):
        self.traffic_data = traffic_data
        self.arima_order = arima_order

    def detect(self):
        X = self.traffic_data.pr

        train_size = int(len(X) * 0.66)
        train, test = X[0:train_size], X[train_size:]

        return self._forecast(train, test, self.arima_order)

    def _forecast(self, train, test, arima_order=(5, 1, 0), log=False):
        history = [x for x in train]
        predictions = list()
        lp_scores = list()

        zero_pred_error = 1
        index = 0

        for idx, t in test.items():

            model = ARIMA(history, order=arima_order)
            model_fit = model.fit(disp=0)
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
        indexes = [lp_score['index'] for lp_score in lp_scores if lp_score['val'] < 0]
        anomaly_traffic = self.traffic_data.loc[indexes, :]

        if log:
            print('Test MSE: %.3f' % error)
            pyplot.plot(test)
            pyplot.plot(predictions, color='red')
            pyplot.show()

            pyplot.plot(lp_scores)
            pyplot.show()

        return anomaly_traffic
