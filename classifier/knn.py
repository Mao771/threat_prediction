"""
The KNNClassifier module contains the implementation for K Nearest Neighbors
Classifcation from the scikit-learn library.
"""

from typing import List

import numpy as np
import pandas as pd

from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import GridSearchCV


class KNNClassifier():
    """
    The Sklearn K-Nearest Neighbors Classification with HyperParameters
    selection using Five Fold Cross Validation.
    """
    def __init__(self, training_data: pd.DataFrame, prediction_data: pd.DataFrame):
        target_column_index = len(training_data.columns) - 1
        target_column = training_data.columns[target_column_index]

        temp_df_train = training_data.drop(target_column, axis=1)
        temp_df_test = prediction_data.drop(target_column, axis=1)

        self.tuned_parameters = {
                    'n_neighbors': range(1, 10),
                    'algorithm': ['ball_tree', 'kd_tree', 'brute'],
                    'weights': ['uniform', 'distance'],
                    'p': [1, 2]
                }
        self.cross_validation = 5

        self.x_train = temp_df_train.to_numpy()
        self.y_train = training_data[target_column].to_numpy()

        self.x_predict = temp_df_test.to_numpy()
        self.model = self.do_train(self.x_train, self.y_train)

    def do_train(self, x_train: np.array, y_train: np.array, **kwargs):

        for each_argument in kwargs:
            self.tuned_parameters.pop(each_argument, '')

        knn_sklearn = KNeighborsClassifier()
        knn_sklearn.fit(x_train, y_train)

        grid_search = GridSearchCV(knn_sklearn, self.tuned_parameters,
                                   cv=self.cross_validation)
        grid_search.fit(x_train, y_train)
        return grid_search

    def predict(self) -> np.array:
        return self.model.predict(self.x_predict)
