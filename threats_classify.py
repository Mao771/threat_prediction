from classifier import ModelClassificationFactory
from util.dataset_helper import get_traffic_threats, replace_na

if __name__ == '__main__':
    models_names = ['knn']
    target_column = 'type'

    factory = ModelClassificationFactory()

    dataset = get_traffic_threats(target_column=target_column)
    replace_na(dataset, 'usage_system', 'usage_user', 'used_percent', 'buffered', 'cached')
    X, y = dataset.iloc[:, 1:12], dataset[target_column]

    for model_name in models_names:
        model = factory.create_model(model_name, x_real=X, y_real=y)
        model.train()
        print(model.calculate_score())
