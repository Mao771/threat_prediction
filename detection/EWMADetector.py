import pandas as pd
from matplotlib import pyplot


class EWMADetector():
    def __init__(self,
                 df_traffic: pd.DataFrame):
        self.df_traffic = df_traffic

    def detect(self,
               alpha: float = 0.15,
               beta: int = 3,
               plot: bool=True):
        X = self.df_traffic.pr
        ewma_traffic = X.ewm(alpha=alpha, adjust=False).mean()

        replace_nan = X.mean()
        anomalies = X.ge(beta * ewma_traffic.shift(), fill_value=replace_nan)
        indexes = anomalies[anomalies == True].index
        anomaly_traffic = self.df_traffic.iloc[[idx - 1 for idx in indexes.values], :]

        if plot:
            data = pd.DataFrame({
                'index': X.index,
                'Original': X,
                'EWMA': ewma_traffic
            })

            ax = data.plot(x="index", y="Original", legend=False)
            ax2 = ax.twinx()
            data.plot(x="index", y="EWMA", ax=ax2, legend=False, color="r")
            ax.figure.legend()
            pyplot.show()

        return anomaly_traffic
