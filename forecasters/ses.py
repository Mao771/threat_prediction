import pandas as pd
from statsmodels.tsa.api import SimpleExpSmoothing
from .ModelBase import ModelBase
from .ModelFactory import ModelFactory
from hyperopt import hp

import warnings
warnings.filterwarnings("ignore")


@ModelFactory.register('ses')
class SesModel(ModelBase):

    def __init__(self, series_train: pd.Series):
        super().__init__(series_train)

        self.model = SimpleExpSmoothing
        self.best_parameters = {
            'smoothing_level': 0.3,
            'optimized': False
        }

    def forecast(self, horizon: int):
        model_fit = SimpleExpSmoothing(self.series_train).fit(**self.best_parameters)

        return model_fit.forecast(horizon)

    def tune_model(self, series_tune: pd.Series = None, max_evals: int = 3) -> float:
        space_ses = {
            'smoothing_level': hp.loguniform('smoothing_level', 0.1, 0.7),
            'optimized': hp.choice('optimized', [True, False])
        }

        return self._bayes_hyper_tune(space_ses, max_evals)
