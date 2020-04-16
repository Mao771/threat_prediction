from util import DbHelper
from definitions import ROOT_DIR
import os
from sklearn.metrics import mean_squared_error
from pandas import DataFrame
from matplotlib import pyplot
from statsmodels.graphics.tsaplots import plot_pacf, plot_acf
from statsmodels.tsa.seasonal import seasonal_decompose
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima_model import ARIMA
from pandas.plotting import autocorrelation_plot
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings("ignore")


if __name__ == '__main__':
    conf = os.path.join(ROOT_DIR, 'settings.conf')
    db_helper = DbHelper(conf)

    series_net = db_helper.get(measurements='net',
                               aggregation='WHERE interface=\'em0\'',
                               fields=('non_negative_difference(packets_recv) as pr',
                                       'non_negative_difference(packets_sent) as ps',
                                       'non_negative_difference(bytes_recv) as br',
                                       'non_negative_difference(bytes_sent) as bs'))

    series_net['packets_rate'] = series_net.pr / series_net.ps
    pyplot.plot(series_net.packets_rate)
    pyplot.show()