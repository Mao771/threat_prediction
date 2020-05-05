from abc import ABC, abstractmethod
from hyperopt import fmin, tpe, space_eval, STATUS_OK, Trials
from sklearn.metrics import mean_squared_error

import pandas as pd


class ModelBase(ABC):

    def __init__(self, series_train: pd.Series):
        self.series_tune = self.series_train = series_train
        self.model = None

    @abstractmethod
    def tune_model(self, series_tune: pd.Series = None, max_evals: int = 3) -> float:
        raise NotImplementedError('Parameter tuning is not implemented')

    def forecast(self, horizon: int):
        if not self.model or not self.best_parameters:
            raise ValueError('Model must be initialized')
        try:
            model_fit = self.model(self.series_train, **self.best_parameters).fit()
        except TypeError:
            model_fit = self.model(self.series_train).fit(**self.best_parameters)

        return model_fit.forecast(horizon)

    def _split_series(self):
        train_size = int(len(self.series_tune) * 0.8)
        train, test = self.series_tune[0:train_size], self.series_tune[train_size:]

        return train, test

    def _bayes_hyper_tune(self, space: dict, max_evals: int = 3) -> float:
        trials = Trials()

        hp_assignments = fmin(fn=self._evaluate_model,
                              space=space,
                              trials=trials,
                              algo=tpe.suggest,
                              verbose=False,
                              max_evals=max_evals)

        self.best_parameters = space_eval(space, hp_assignments)

        return min(trials.losses())

    def _evaluate_model(self, params):
        if not self.model:
            raise ValueError('Model must be initialized')

        train, test = self._split_series()
        history = [x for x in train]
        predictions = list()

        for t in range(len(test)):
            try:
                model_fit = self.model(history, **params).fit(disp=0)
            except TypeError:
                model_fit = self.model(history).fit(**params)

            output = model_fit.forecast()
            y_pred = output[0]
            y_real = test[t]

            predictions.append(y_pred)
            history.append(y_real)

        error = mean_squared_error(test, predictions)

        return {'loss': error, 'status': STATUS_OK}
