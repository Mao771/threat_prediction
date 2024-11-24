import time

import os

import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.feature_extraction.text import CountVectorizer

# import other required libs
import pandas as pd
import numpy as np

# string manipulation libs
import re

# viz libs
import matplotlib

matplotlib.use('TkAgg')
import seaborn as sns

from itertools import groupby
import json

from sklearn.svm import SVC
from sklearn.linear_model import SGDClassifier

from elf_parser import parse_file
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import f1_score
from sklearn.model_selection import GridSearchCV
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import learning_curve
from sklearn.model_selection import ShuffleSplit, validation_curve
from sklearn.linear_model import LogisticRegression

from xgboost import XGBClassifier
import sys
from io import StringIO
from sklearn.decomposition import TruncatedSVD

virus_analysis = {}
input_dataframe = pd.DataFrame(virus_analysis)
input_dataframe = input_dataframe.fillna(0).transpose()
input_dataframe = input_dataframe.apply(lambda s: s.apply(lambda c: c and c["result"]))
input_dataframe = input_dataframe.replace(to_replace=0, value='undetected').fillna(value='undetected')

viruses_count = len(virus_analysis)
SECTION_NAME = '.rodata'

index = 1
parsed_count = 0
files = {}

VIRUS_FOLDER = "D:\\Documents\\VirusShare_ELF_20200405"
FAILED_TO_DISASSEMBLE = "Failed to disassemble"
OPCODES_COLUMN = "processed_opcodes"
OPCODES_ORIGINAL_COLUMN = "original_opcodes"

FILENAME_RAW = f"files_{SECTION_NAME}.csv"
FILENAME_WITH_UNDETECTED = "viruses_rodata_Microsoft_with_undetected.csv"
FILENAME = FILENAME_WITH_UNDETECTED

if os.path.exists(FILENAME):
    df = pd.read_csv(FILENAME)
else:
    for f_name in virus_analysis.keys():
        print(f_name)
        commands = []
        original_commands = []
        try:
            if parsed_count == 4709:
                parsed_count += 1
                continue
            file_commands = parse_file(os.path.join(VIRUS_FOLDER, f"VirusShare_{f_name}"), SECTION_NAME)
            for command in file_commands:
                original_commands.append(command)
                text = re.sub("0x[0-9a-zA-Z]{4,8}", '', command)
                commands.append(text)
            parsed_count += 1
        except Exception as e:
            print(f"{f_name} exception {str(e)}")
        except TimeoutError as e:
            print(f"{f_name} parse timeout")
        print(f"parsed: {parsed_count}/{viruses_count}")
        files[f_name] = {
            "original_opcodes": " ".join(
                [key for key, _group in groupby(original_commands)]) if original_commands else FAILED_TO_DISASSEMBLE,
            OPCODES_COLUMN: " ".join([key for key, _group in groupby(commands)]) if commands else FAILED_TO_DISASSEMBLE
        }
        index += 1

    df = pd.DataFrame.from_dict(data=files, columns=["original_opcodes", OPCODES_COLUMN], orient="index")
    df = df.fillna("")
    df = df.drop(df[df[OPCODES_COLUMN] == FAILED_TO_DISASSEMBLE].index)
    df = pd.concat(objs=[input_dataframe, df], axis=1)
    df.to_csv(f"files_{SECTION_NAME}.csv")

df = df.dropna()

from sklearn.model_selection import train_test_split
from utils import plot_learning_curve, plot_grid_search
import seaborn as sns
from sklearn.linear_model import LinearRegression


def plot_confusion_matrix(actual, predicted):
    actual_predicted_df = pd.DataFrame({"actual": actual, "predicted": predicted, "count": np.ones(len(actual))})
    actual_predicted_df = actual_predicted_df.pivot_table(values="count", index=["actual", "predicted"], aggfunc="sum")
    actual_predicted_df = actual_predicted_df.reset_index(level=[0, 1]).pivot(index="actual", columns="predicted",
                                                                              values="count")
    sns.heatmap(actual_predicted_df, annot=True, fmt=".4g")
    plt.show()


def output_metrics(actual, predicted, classifier_name, parameters: list = None):
    mean_accuracy = np.mean(actual == predicted)
    f1_weighted = f1_score(actual, predicted, average="weighted")

    print(f"Accuracy for {classifier_name}: mean accuracy = {mean_accuracy}, f1 = {f1_weighted}. "
          f"Parameters: {parameters}")


CLASSES_LABELS = [0, 1, 2, 3]
CLASSES_STR = ["Gafgyt", "Mirai", "Tsunami", "Lightaidra", "Ganiw", "Dofloo", "BASHLITE", "undetected"]
N_GRAM_RANGES = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)]
ANTIVIRUSES_REFINED = ["ClamAV", "FireEye", "McAfee", "Zillya", "Cyren", "ESET-NOD32", "Lionic", "TrendMicro-HouseCall",
                       "BitDefender", "NANO-Antivirus", "Ad-Aware", "F-Secure", "TrendMicro",
                       "McAfee-GW-Edition", "Emsisoft", "Ikarus", "Avast-Mobile", "Avira", "Antiy-AVL", "Microsoft",
                       "GData", "Fortinet"]

ANTIVIRUSES_0_6_ACCURACY = ["Antiy-AVL", "GData"]
ANTIVIRUSES_0_7_ACCURACY = ["FireEye", "McAfee", "Zillya", "Cyren", "ESET-NOD32", "BitDefender", "NANO-Antivirus",
                            "Ad-Aware", "F-Secure", "TrendMicro", "McAfee-GW-Edition", "Emsisoft"
                                                                                       "Avira", "Fortinet"]
ANTIVIRUSES_0_8_ACCURACY = ["Ikarus", "Avast-Mobile"]
ANTIVIRUSES_SELECTED = ["virus"]
CLASSES_STR_SELECTED = ["Gafgyt", "Mirai", "Lightaidra", "not a virus"]
N_GRAM_SELECTED = [(4, 4)]

for antivirus in ANTIVIRUSES_SELECTED:
    for class_str in CLASSES_STR_SELECTED:
        df.loc[df[antivirus].str.contains(class_str, case=False), antivirus] = class_str
    df.loc[df[antivirus] == "undetected", antivirus] = "not a virus"
    df_copy = df[df[antivirus].isin(CLASSES_STR_SELECTED)].copy()

    if len(df_copy[antivirus]) == 0:
        continue

    # tf-idf transformer
    try:
        train, test = train_test_split(df_copy, test_size=0.2)

        train_x = train[OPCODES_COLUMN]
        train_y: pd.Series = train[antivirus]
        test_x = test[OPCODES_COLUMN]
        test_y: pd.Series = test[antivirus]

        for n_gram in N_GRAM_SELECTED:
            start_time = time.time()
            count_vect = CountVectorizer(ngram_range=n_gram)
            X_train_counts = count_vect.fit_transform(train_x)
            X_test_counts = count_vect.transform(test_x)
            # feature_selection = TruncatedSVD()
            # X_train_counts = feature_selection.fit_transform(X_train_counts, train_y)
            # X_test_counts = feature_selection.fit_transform(X_test_counts, test_y)
            tf_idf_vectorizer = TfidfTransformer()
            X_train_tfidf = tf_idf_vectorizer.fit_transform(X_train_counts)
            X_test_tfidf = tf_idf_vectorizer.transform(X_test_counts)
            print(train_y.value_counts())
            print(test_y.value_counts())
            print(time.time() - start_time)
            # pd.set_option('display.max_colwidth', None)
            # print(train_x[100:110])

            # print("Evaluating MultinomialNB")
            # cv = ShuffleSplit(n_splits=50, test_size=0.3, random_state=0)
            # multinomial_nb = MultinomialNB(alpha=0.01, fit_prior=True)
            # plot_learning_curve(
            #     multinomial_nb,
            #     "Multinomial Naive Bayes",
            #     X_train_tfidf,
            #     train_y,
            #     ylim=(0.7, 1.01),
            #     cv=cv,
            #     n_jobs=4,
            #     scoring="accuracy",
            # )
            # multinomial_nb = MultinomialNB(alpha=0.001, fit_prior=True)
            # multinomial_nb.fit(X_train_tfidf, train_y)
            # predicted = multinomial_nb.predict(X_test_tfidf)
            # output_metrics(test_y, predicted, multinomial_nb.get_params())
            # plot_confusion_matrix(test_y, predicted)

            # {'alpha': 0.0001, 'fit_prior': True}
            # multinomial_nb = MultinomialNB()
            # multinomial_nb_params = {
            #     'fit_prior': [False, True],
            #     'alpha': [0.0001, 0.001, 0.01, 0.1, 0.5, 1],
            # }
            # grid_search_nb = GridSearchCV(multinomial_nb, multinomial_nb_params)
            # grid_search_nb.fit(X=X_train_tfidf, y=train_y)
            # best_estimator_multinomial_nb = grid_search_nb.best_estimator_
            # # plot_learning_curve(
            # #     best_estimator_multinomial_nb,
            # #     "Multinomial Naive Bayes",
            # #     X_train_tfidf,
            # #     train_y,
            # #     ylim=(0.7, 1.01),
            # #     cv=cv,
            # #     n_jobs=4,
            # #     scoring="accuracy",
            # # )
            # start_time = time.time()
            # predicted = best_estimator_multinomial_nb.predict(X=X_test_tfidf)
            # finish_time = time.time()
            # output_metrics(test_y, predicted, best_estimator_multinomial_nb.__class__, grid_search_nb.best_params_)
            # print("Time MultinomialNB %f" % (finish_time - start_time))
            # # plot_confusion_matrix(test_y, predicted)
            #
            # svc = SVC(C=0.9, kernel='rbf')
            # results = svc.fit(X_train_tfidf, train_y)
            # predict = svc.predict(X_test_tfidf)
            # plot_learning_curve(
            #     svc,
            #     "SVC learning curve",
            #     X_train_tfidf,
            #     train_y,
            #     ylim=(0.7, 1.01),
            #     cv=ShuffleSplit(n_splits=50, test_size=0.3, random_state=21),
            #     n_jobs=4,
            #     scoring="accuracy",
            # )
            # print("Evaluating SVC")
            # svc = SVC() # {'gamma': 'scale', 'kernel': 'rbf'}
            # C = list(np.arange(0.1, 1, 0.1))
            # kernel = ['linear', 'poly', 'rbf', 'sigmoid']
            # svc_params = {
            #     'C': C,
            #     'kernel': kernel
            # }
            # grid_search_svc = GridSearchCV(svc, svc_params)
            # grid_search_svc.fit(X=X_train_tfidf, y=train_y)
            # best_estimator = grid_search_svc.best_estimator_
            # plot_grid_search(grid_search_svc.cv_results_, "kernel", "C")
            # print(grid_search_svc.best_params_)
            # cv = ShuffleSplit(n_splits=50, test_size=0.3, random_state=0)
            # best_estimator = SVC(C=0.9, kernel='rbf')
            # best_estimator.fit(X_train_tfidf, train_y)
            # predicted = best_estimator.predict(X_test_tfidf)
            # output_metrics(test_y, predicted, "SVC")
            # plot_confusion_matrix(test_y, predicted)
            # best_estimator_svc = SVC(C=0.9, kernel='rbf')
            # plot_learning_curve(
            #     best_estimator_svc,
            #     "SVC",
            #     X_train_tfidf,
            #     train_y,
            #     ylim=(0.7, 1.01),
            #     cv=cv,
            #     n_jobs=4,
            #     scoring="accuracy",
            # )
            # start_time = time.time()
            # predicted = best_estimator_svc.predict(X=X_test_tfidf)
            # print(f"time SVC: {time.time() - start_time}")
            # output_metrics(test_y, predicted, "SVC", grid_search_svc.best_params_)

            # lr = LinearRegression()
            # lr.fit(X_train_tfidf, train_y_nums)
            # predicted = lr.predict(X_test_tfidf)
            # print(np.mean(predicted == test_y_nums))

            # old_stdout = sys.stdout
            # sys.stdout = mystdout = StringIO()

            # clf = SGDClassifier(alpha=0.0001, l1_ratio=0.15, loss='perceptron', verbose=1, validation_fraction=0.2)
            start_time = time.time()
            sgd = SGDClassifier(loss="log_loss", verbose=1, average=True)
            cv = ShuffleSplit(n_splits=50, test_size=0.3, random_state=0)
            plot_learning_curve(
                sgd,
                "SGD",
                X_train_tfidf,
                train_y,
                ylim=(0.7, 1.01),
                cv=cv,
                n_jobs=4,
                scoring="accuracy",
            )
            sgd.fit(X_train_tfidf, train_y)
            predicted = sgd.predict(X_test_tfidf)
            print(time.time() - start_time)
            output_metrics(test_y, predicted, "SGD")
            # sys.stdout = old_stdout
            # loss_history = mystdout.getvalue()
            # loss_list = []
            # for line in loss_history.split('\n'):
            #     if (len(line.split("loss: ")) == 1):
            #         continue
            #     loss_list.append(float(line.split("loss: ")[-1]))

            # sys.stdout = mystdout = StringIO()
            # for _ in range(20):
            #     clf.partial_fit(X_test_tfidf, test_y)
            # sys.stdout = old_stdout
            # loss_val_history = mystdout.getvalue()
            # loss_val_list = []
            # for line in loss_val_history.split('\n'):
            #     if (len(line.split("loss: ")) == 1):
            #         continue
            #     loss_val_list.append(float(line.split("loss: ")[-1]))
            #
            # plt.figure()
            # plt.plot(np.arange(len(loss_list)), loss_list)
            # # plt.plot(np.arange(len(loss_val_list)), loss_val_list)
            # plt.xlabel("Time in epochs")
            # plt.ylabel("Loss")
            # plt.savefig(f"loss.png")
            # plt.close()

            # print("Evaluating SGD")
            # alpha = [0.00001, 0.0001, 0.001, 0.01, 0.1]
            # penalty = ['l1', 'l2']
            # loss = ["huber", "hinge", "log_loss", "modified_huber"]
            # learning_rate = ['constant', 'optimal', 'invscaling', 'adaptive']
            # tol = [0.00001, 0.0001, 0.001, 0.01, 0.1]
            # eta = [0.00001, 0.0001, 0.001, 0.01, 0.1]
            # sgd_classifier = SGDClassifier()  # {'alpha': 0.0001, 'l1_ratio': 0.15, 'loss': 'modified_huber'}
            # sgd_params = {
            #     'eta0': eta,
            #     'learning_rate': learning_rate
            # }
            # grid_search_sgd = GridSearchCV(sgd_classifier, sgd_params)
            # grid_search_sgd.fit(X=X_train_tfidf, y=train_y)
            # print(grid_search_sgd.best_params_, grid_search_sgd.best_score_)
            # plot_grid_search(grid_search_sgd.cv_results_, "learning_rate", "eta0")
            # best_estimator_sgd = grid_search_sgd.best_estimator_
            # # plot_learning_curve(
            # #     best_estimator_sgd,
            # #     "SGD",
            # #     X_train_tfidf,
            # #     train_y,
            # #     ylim=(0.7, 1.01),
            # #     cv=cv,
            # #     n_jobs=4,
            # #     scoring="accuracy",
            # # )
            # start_time = time.time()
            # best_estimator_sgd = grid_search_sgd.best_estimator_
            # predicted = best_estimator_sgd.predict(X=X_test_tfidf)
            # output_metrics(test_y, predicted, "SGDClassifier", grid_search_sgd.best_params_)
            # plot_confusion_matrix(test_y, predicted)
            # sgd_best = SGDClassifier(fit_intercept=False, early_stopping=True)
            # print(sgd_best.get_params())
            #
            # best_sgd = SGDClassifier(eta0=0.01, learning_rate='optimal')
            # best_sgd = SGDClassifier(eta0=0.001, learning_rate='optimal')
            # plot_learning_curve(
            #     best_sgd,
            #     "SGD learning curve",
            #     X_train_tfidf,
            #     train_y,
            #     ylim=(0.7, 1.01),
            #     cv=ShuffleSplit(n_splits=50, test_size=0.3, random_state=0),
            #     n_jobs=4,
            #     scoring="accuracy",
            # )
            # best_sgd.fit(X_train_tfidf, train_y)
            # predicted = best_sgd.predict(X_test_tfidf)
            # output_metrics(test_y, predicted, "SGD classifier")
            # plot_confusion_matrix(test_y, predicted)
            #
            test_y_nums = test_y.map(lambda x: CLASSES_STR_SELECTED.index(x))
            train_y_nums = train_y.map(lambda x: CLASSES_STR_SELECTED.index(x))

            # print("Tunning XGBClassifier")
            # booster = ["gbtree", "gblinear"]
            # objective = ["multi:softmax", "multi:softprob"]
            # learning_rate = [0.00001, 0.0001, 0.001, 0.01, 0.1, 1]
            # max_depth = [5, 6, 7, 8]
            # xgb_classifier = XGBClassifier(num_class=4) # {'alpha': 0, 'booster': 'gblinear', 'lambda': 0, 'learning_rate': 0.001}
            # xgb_parameters_grid = {
            #     "learning_rate": learning_rate,
            #     "max_depth": max_depth
            # }
            # grid_search_xgb = GridSearchCV(xgb_classifier, xgb_parameters_grid)
            # grid_search_xgb.fit(X=X_train_tfidf, y=train_y_nums)
            # plot_grid_search(grid_search_xgb.cv_results_, "max_depth", "learning_rate", logit=True)

            # best_xgb = XGBClassifier(learning_rate=0.1, max_depth=7)
            # plot_learning_curve(
            #     best_xgb,
            #     "XGBoost learning curve",
            #     X_train_tfidf,
            #     train_y_nums,
            #     ylim=(0.7, 1.01),
            #     cv=ShuffleSplit(n_splits=50, test_size=0.3, random_state=0),
            #     n_jobs=4,
            #     scoring="accuracy",
            # )
            # best_xgb = XGBClassifier(learning_rate=0.1, max_depth=7)
            # best_xgb.fit(X_train_tfidf, train_y_nums)
            # predictions_xgb = best_xgb.predict(X_test_tfidf)
            # output_metrics(test_y_nums, predictions_xgb, best_xgb.get_params())
            # plot_confusion_matrix([CLASSES_STR_SELECTED[x] for x in test_y_nums], [CLASSES_STR_SELECTED[x] for x in predictions_xgb])
            # results = xgb_classifier.evals_result()
            # output_metrics(test_y_nums, predictions_xgb, "XGBoost")
            # plt.plot(results['validation_0']['mlogloss'], label='train')
            # plt.plot(results['validation_1']['mlogloss'], label='test')
            # plt.legend()
            # plt.show()

            # grid_search_xgb = GridSearchCV(xgb_classifier, xgb_parameters_grid)
            # grid_search_xgb.fit(X_train_tfidf, train_y)
            # best_estimator_xgb =grid_search_xgb.best_estimator_
            # plot_learning_curve(
            #     best_estimator_xgb,
            #     "XGB",
            #     X_train_tfidf,
            #     train_y,
            #     ylim=(0.7, 1.01),
            #     cv=cv,
            #     n_jobs=4,
            #     scoring="accuracy",
            # )
            # start_time = time.time()
            # predicted = best_estimator_xgb.predict(X=X_test_tfidf)
            # output_metrics(test_y, predicted, "XGBoost", grid_search_xgb.best_params_)
            # print(f"time: {time.time() - start_time}")
            # plot_confusion_matrix(test_y, predicted)
    except Exception as e:
        print(str(e))
