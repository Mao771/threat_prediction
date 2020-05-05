from util import get_threats, DbHelper
from definitions import SETTINGS_FILE
from forecasters import ModelFactory

if __name__ == '__main__':
    db_helper = DbHelper(SETTINGS_FILE)

    df_threats = get_threats()
    model_names = ['ses']

    result_points = []
    best_model, best_score = None, float("inf")

    for column in df_threats.columns:
        if isinstance(column, tuple):
            threats_name = column[1]
        else:
            threats_name = column

        for model_name in model_names:
            model = ModelFactory.create_model(model_name, series_train = df_threats[column])
            score = 0#model.tune_model(max_evals=2)

            if score < best_score:
                best_model = model

        series_result = best_model.forecast(10)
        dict_series = series_result.to_dict()

        for k, v in dict_series.items():
            result_points.append({
                "measurement": "threats_predictions",
                "time": k,
                "fields": {
                    threats_name: int(v)
                }
            })

    db_helper.write(result_points)
