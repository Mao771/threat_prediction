from classifier import ModelClassificationFactory, ModelClassificationBase

from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import GridSearchCV


@ModelClassificationFactory.register('knn')
class KNNClassifier(ModelClassificationBase):
    """
    The Sklearn K-Nearest Neighbors Classification with HyperParameters
    selection using Five Fold Cross Validation.
    """
    def __init__(self, x_real, y_real):
        super().__init__(x_real, y_real)

        self.tuned_parameters = {
            'n_neighbors': range(1, 10),
            'algorithm': ['ball_tree', 'kd_tree', 'brute'],
            'weights': ['uniform', 'distance'],
            'p': [1, 2]
        }
        self.cross_validation = 5
        self.model = None

    def train(self):
        knn_sklearn = KNeighborsClassifier()
        knn_sklearn.fit(self.x_train, self.y_train)

        grid_search = GridSearchCV(knn_sklearn, self.tuned_parameters,
                                   cv=self.cross_validation)
        grid_search.fit(self.x_train, self.y_train)
        self.model = grid_search
        self.y_pred = self.model.predict(self.x_test)

        return grid_search

    def predict(self, x_predict):
        return self.model.predict(x_predict)
