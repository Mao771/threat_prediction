from statsmodels.tsa.arima_model import ARIMA
from .ModelBase import ModelBase
from .ModelFactory import ModelFactory
from hyperopt import hp

import pandas as pd

import warnings
warnings.filterwarnings("ignore")


@ModelFactory.register('arima')
class Arima(ModelBase):

    def __init__(self, series_train: pd.Series):
        super().__init__(series_train)

        self.model = ARIMA
        self.best_parameters = {
            'order': (1, 1, 0)
        }

    def tune_model(self, series_tune: pd.Series = None, max_evals: int = 3) -> float:
        if series_tune:
            self.series_tune = series_tune

        space_arima = {
            'order': (hp.choice('p', range(0, 3)),
                      hp.choice('d', range(0, 3)),
                      hp.choice('q', range(0, 3)))
        }

        return self._bayes_hyper_tune(space_arima, max_evals)
