from util import get_threats
from forecasters import ModelFactory

if __name__ == '__main__':
    df_threats = get_threats()
    model_names = ['ses']

    for column in df_threats.columns:
        for model_name in model_names:
            model = ModelFactory.create_model(model_name, series_train = df_threats[column])
            print(model.tune_model(max_evals=2))
