from abc import ABC, abstractmethod
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


class ModelClassificationBase(ABC):

    def __init__(self, x_real, y_real,
                 test_size: float = 0.3,
                 random_state: int = 42):
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(x_real, y_real,
                                                                                test_size=test_size,
                                                                                random_state=random_state)
        self.y_pred = None

    @abstractmethod
    def train(self):
        raise NotImplementedError('Method train must be implemented')

    @abstractmethod
    def predict(self, x_predict):
        raise NotImplementedError('Method predict must be implemented')

    def calculate_score(self):
        if not self.y_pred:
            raise ValueError('Method train must be called first')

        return {
            'accuracy': accuracy_score(self.y_test, self.y_pred),
            'precision': precision_score(self.y_test, self.y_pred),
            'recall': recall_score(self.y_test, self.y_pred),
            'f1': f1_score(self.y_test, self.y_pred)
        }
