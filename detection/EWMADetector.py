import pandas as pd
from matplotlib import pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)


class EWMADetector:
    def __init__(self,
                 df_traffic: pd.DataFrame):
        self.df_traffic = df_traffic[~df_traffic.index.duplicated()]

    def detect(self,
               traffic_parameter='pr',
               traffic_parameter_name='Packets received',
               alpha: float = 0.3,
               beta: int = 2.5,
               plot: bool = True):
        X = self.df_traffic[traffic_parameter]
        df_scaled = pd.DataFrame(X.reset_index(drop=True))
        # scaler = StandardScaler()
        # df_scaled = pd.DataFrame(scaler.fit_transform(pd.DataFrame(X.reset_index(drop=True))))

        df_scaled.columns.values[0] = 'value'
        df_scaled['hour'] = X.index.hour
        # df_scaled['minute'] = X.index.minute

        isolation_forest = IsolationForest(contamination=0.01)
        preds = isolation_forest.fit_predict(df_scaled)

        anomaly_indicies_if = X.index[[idx for idx, val in enumerate(preds) if val == -1]]

        ewma_traffic = X.ewm(alpha=alpha, adjust=False).mean()
        anomalies = X.gt(beta * ewma_traffic.shift())
        anomaly_indices = anomalies[anomalies == True].index
        anomaly_traffic = self.df_traffic.loc[anomaly_indices, :]
        anomaly_traffic_if = self.df_traffic.loc[anomaly_indicies_if, :]

        if plot:
            data = pd.DataFrame({
                'index': X.index,
                traffic_parameter_name: X,
                'EWMA': ewma_traffic
            })

            # Plot traffic data
            ax = data.plot(x="index", y=traffic_parameter_name, legend=False, color='blue', label=f"Network {traffic_parameter_name}")
            ax2 = ax.twinx()
            data.plot(x="index", y="EWMA", ax=ax2, legend=False, color="red", label="EWMA")

            ax.scatter(anomaly_indices,
                       anomaly_traffic[traffic_parameter].values,
                       color='orange',
                       label='DDoS EWMA',
                       s=150,
                       zorder=5)
            ax.scatter(anomaly_indicies_if,
                       anomaly_traffic_if[traffic_parameter],
                       color='green',
                       label='DDoS IF',
                       s=100,
                       zorder=5)
            ax.figure.legend()
            ax.set_xlabel("Day Hour:Minute")
            ax.set_ylabel(traffic_parameter_name)
            plt.title("Traffic Data with DDoS")
            plt.show()

        return anomaly_traffic, anomaly_traffic_if



# import matplotlib.pyplot as plt
# from sklearn.inspection import DecisionBoundaryDisplay
# scatter = plt.scatter(df_scaled.iloc[:, 0], df_scaled.iloc[:, 1], s=20, edgecolor="k")
# handles, labels = scatter.legend_elements()
# plt.legend(handles=handles, labels=["outliers", "inliers"], title="true class")
# plt.title("Traffic packets received")
# plt.show()
# disp = DecisionBoundaryDisplay.from_estimator(
#     isolation_forest,
#     df_scaled,
#     response_method="predict",
#     alpha=0.5
# )
# disp.ax_.scatter(df_scaled.iloc[:, 0], df_scaled.iloc[:, 1], c=preds, s=20, edgecolor="k")
# disp.ax_.set_title("Traffic in context of hour\n decision boundary")
# plt.legend(handles=handles, labels=["DDoS", "Benign"], title="Class")
# plt.show()
