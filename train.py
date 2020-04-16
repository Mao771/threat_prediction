import os
import pandas as pd
import numpy as np
from classifier import KNNClassifier


def shuffle(filename):
    df = pd.read_csv(filename, header=0,dtype=object,na_filter=False)
    return df.reindex(np.random.permutation(df.index))


if __name__ == '__main__':

    input_df = shuffle(os.path.abspath('train_data/kddcup.data_10_percent_corrected'))
#   train_file_path = os.path.abspath('train_data/kddcup.data_10_percent_corrected')
#   test_file_path = os.path.abspath('train_data/kddcup.data_10_percent')
#   train_data = pd.read_csv(train_file_path)
#   test_data = pd.read_csv(test_file_path)
    print(input_df.head())

    train_data_parameter = input_df.drop(input_df.columns[[1, 2, 3]], axis=1)
    knn = KNNClassifier(train_data_parameter.iloc[:100000, :], train_data_parameter.iloc[100000:130000, :])
