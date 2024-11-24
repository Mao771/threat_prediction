import os
import pickle
import time
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.feature_extraction.text import CountVectorizer
import pandas as pd
import numpy as np
import matplotlib
from sklearn.linear_model import RidgeClassifier, MultiTaskLasso, MultiTaskElasticNet, MultiTaskElasticNetCV, MultiTaskLassoCV
from sklearn.linear_model import SGDClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import f1_score
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
import seaborn as sns
from sklearn import metrics
from sklearn.decomposition import TruncatedSVD
from sklearn.model_selection import GridSearchCV
from parse_pe_file import parse_pe_imports
from sklearn.model_selection import ShuffleSplit, validation_curve
from sklearn.decomposition import SparsePCA, PCA

from utils import plot_grid_search, plot_learning_curve, plot_loss_on_dataset, plot_roc_curve, plot_roc_multiple
from time import time

from sklearn.datasets import fetch_lfw_people
from sklearn.decomposition import PCA
from sklearn.metrics import ConfusionMatrixDisplay, classification_report
from sklearn.model_selection import RandomizedSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler
import gensim
import nltk
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('punkt_tab')
from nltk.corpus import stopwords

PLOT_GRAPHICS = True

matplotlib.use('TkAgg')


from hpsklearn import HyperoptEstimator


def plot_confusion_matrix(actual, predicted):
    if not PLOT_GRAPHICS:
        return
    actual_predicted_df = pd.DataFrame({"actual": actual, "predicted": predicted, "count": np.ones(len(actual))})
    actual_predicted_df = actual_predicted_df.pivot_table(values="count", index=["actual", "predicted"], aggfunc="sum")
    actual_predicted_df = actual_predicted_df.reset_index(level=[0, 1]).pivot(index="actual", columns="predicted",
                                                                              values="count")
    sns.heatmap(actual_predicted_df, annot=True, fmt=".4g")
    plt.show()


def output_metrics(actual, predicted, classifier_name, parameters: list = None):
    mean_accuracy = np.mean(actual == np.array([p[0] for p in predicted]))
    f1_weighted = f1_score(actual, predicted, average="weighted")

    print(f"Accuracy for {classifier_name}: mean accuracy = {mean_accuracy}, f1 = {f1_weighted}. "
          f"Parameters: {parameters}")


CLASSES_LABELS = [0, 1, 2, 3]
CLASSES_STR_SELECTED = ['Trojan:Win32', 'Backdoor:Win32', 'PUA:Win32', 'not a virus']
N_GRAM_SELECTED = [(1, 1)]

# df_x = pd.read_csv("/home/max/Downloads/mal-api-2019/all_analysis_data.txt")
# df_y = pd.read_csv("/home/max/Downloads/mal-api-2019/labels.txt").replace('Backdoor', 'Trojan').replace('Virus', 'Worms').replace('Downloader', 'Adware').replace('Spyware', 'Dropper')
# df = pd.concat([df_x, df_y], ignore_index=True, axis=1).rename(columns={0: "label", 1: "api_calls"})

# df = pd.read_csv("resdlls.csv", header=None).rename(columns={0: "label", 1: "api_calls"}).fillna("")


# df_virus = pd.read_csv('parsed_malware_pe_1.csv').dropna()
# df_virus = df_virus[df_virus['parsed']!='FAILED TO PARSE']
# df_not_virus = pd.read_csv('parsed_malware_pe_bening.csv').dropna()
# df_not_virus.loc[:, 'type'] = 'bening'
# df_not_virus = df_not_virus[df_not_virus['parsed']!='FAILED TO PARSE']
# df = pd.concat([df_virus, df_not_virus]).reset_index(drop=True)
#
# df = df[df['type'] != 'worm']

# df = pd.read_csv("vsh_result_2").dropna()
# df = df[df['type'] != 'bening'][df['imports'] != 'FAILED TO PARSE']
# print(df['type'].value_counts())
stop_words = set(stopwords.words('english'))


def create_dataset():
    df_virus = pd.read_csv('vsh_result_virus_new').dropna().sample(frac=1).reset_index(drop=True)
    df_virus = df_virus[df_virus['imports']!='FAILED TO PARSE']
    df_not_virus = pd.read_csv('vsh_result_benign_7').dropna() # 5
    df_not_virus = df_not_virus[df_not_virus['imports']!='FAILED TO PARSE'].sample(frac=1).reset_index(drop=True)
    df_adware = df_virus[df_virus['type']=='adware']
    df_trojan = df_virus[df_virus['type']=='trojan']
    df_worm = df_virus[df_virus['type']=='worm']
    # df_virus = df_virus[df_virus['type']!='adware']


    df = pd.concat([df_adware[:4031], df_trojan[:4628], df_worm[:3875], df_not_virus[:4328]]).sample(frac=1).reset_index(drop=True)
    df_proxy = pd.concat([df_adware[4031:4331], df_trojan[4628:], df_worm[3875:], df_not_virus[4328:]]).sample(frac=1).reset_index(drop=True)
    df = df[df['type'] != 'spy']

    df_proxy.to_csv("./train/pe_for_proxy_new.csv")
    df.to_csv('./train/data_pe_new.csv', index=False)

    print(df_proxy['type'].value_counts())
    print(df['type'].value_counts())
    # df['imports'] = df['imports'].apply(lambda x: gensim.utils.simple_preprocess(x))

df = pd.read_csv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "train_dataset")).dropna()

# for bf in os.listdir("/home/max/DikeDataset/files/benign"):
#     if bf.endswith("ole"):
#         continue
#     parse_pe_imports(os.path.join("/home/max/DikeDataset/files/benign", bf))

#
# df = pd.read_csv('pe_files_random.csv', header=0)
# df = df.iloc[:, 1:3].dropna()
from gensim.models import Word2Vec
from nltk.tokenize import word_tokenize
import string


def preprocess(text):
    if isinstance(text, float):
        print(text)
        text = str(text)
    text = text.lower()
    text = ''.join([word for word in text if word not in string.punctuation])
    tokens = word_tokenize(text)
    tokens = [word for word in tokens if word not in stop_words]
    return ' '.join(tokens)


def vectorize(sentence, w2v_model):
    words = sentence.split()
    words_vecs = [w2v_model.wv[word] for word in words if word in w2v_model.wv]
    if len(words_vecs) == 0:
        return np.zeros(100)
    words_vecs = np.array(words_vecs)
    return words_vecs.mean(axis=0)


def tune_random_forest(random_forest, X_train, y_train):
    from sklearn.model_selection import RandomizedSearchCV
    # Number of trees in random forest
    n_estimators = [int(x) for x in np.linspace(start=200, stop=2000, num=10)]
    # Number of features to consider at every split
    max_features = ['auto', 'sqrt']
    # Maximum number of levels in tree
    max_depth = [int(x) for x in np.linspace(10, 110, num=11)]
    max_depth.append(None)
    # Minimum number of samples required to split a node
    min_samples_split = [2, 5, 10]
    # Minimum number of samples required at each leaf node
    min_samples_leaf = [1, 2, 4]
    # Method of selecting samples for training each tree
    bootstrap = [True, False]
    # Create the random grid
    random_grid = {'n_estimators': n_estimators,
                   'max_features': max_features,
                   'max_depth': max_depth,
                   'min_samples_split': min_samples_split,
                   'min_samples_leaf': min_samples_leaf,
                   'bootstrap': bootstrap}


    # Random search of parameters, using 3 fold cross validation,
    # search across 100 different combinations, and use all available cores
    rf_random = RandomizedSearchCV(estimator=random_forest, param_distributions=random_grid, n_iter=30, cv=3, verbose=2,
                                   random_state=42, n_jobs=-1)
    # Fit the random search model
    rf_random.fit(X_train, y_train)

    print(rf_random.best_params_)

    return rf_random.best_estimator_


def tune_mlp(mlp, X_train, y_train):
    from sklearn.model_selection import RandomizedSearchCV

    random_grid = {
        'hidden_layer_sizes': [(1000, 500, 100, 50, 25), (5000, 1000, 500, 100, 50, 25), (100,)],
        'activation': ['identity', 'logistic', 'tanh', 'relu'],
        'solver': ['lbfgs', 'sgd', 'adam'],
        'penalty': ['elasticnet', 'l2'],
        'learning_rate': ['constant', 'invscaling', 'adaptive'],
        'batch_size': [100, 200, 500, 1000, 5000, 10000],
        'n_iter_no_change': [10, 20],
        'learning_rate_init': [0, 0.0000001, 0.000001, 0.0001, 0.001, 0.01, 0.1, 0.15, 0.5, 0.75, 1, 10, 100],
        'alpha': [0, 0.0000001, 0.000001, 0.0001, 0.001, 0.01, 0.1, 0.15, 0.5, 0.75, 1, 10, 100],
        'l1_ratio': [0, 0.0000001, 0.000001, 0.0001, 0.001, 0.01, 0.1, 0.15, 0.5, 0.75, 1, 10, 100],
        'power_t': [0, 0.0000001, 0.000001, 0.0001, 0.001, 0.01, 0.1, 0.15, 0.5, 0.75, 1, 10, 100, 500, 1000, 5000, 10000],
        'momentum': [0, 0.0000001, 0.000001, 0.0001, 0.001, 0.01, 0.1, 0.15, 0.5, 0.75, 0.9, 1, 10, 100, 500, 1000, 5000, 10000],
        'epsilon': [0, 0.0000001, 0.000001, 0.0001, 0.001, 0.01, 0.1, 0.15, 0.5, 0.75, 0.9, 1, 10, 100, 500, 1000, 5000, 10000],
        'validation_fraction': [0.1, 0.2, 0.3, 0.4, 0.5],
        'beta_1': [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
        'beta_2': [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.99],
        'tol': [0, 0.0000001, 0.000001, 0.0001, 0.001, 0.01, 0.1, 0.15, 0.5, 0.75, 1, 10, 100, 500, 1000, 5000, 10000],
        'max_iter': [200, 500, 1000, 5000, 10000]
    }


    # Random search of parameters, using 3 fold cross validation,
    # search across 100 different combinations, and use all available cores
    mlp_random = RandomizedSearchCV(estimator=mlp, param_distributions=random_grid, n_iter=10, cv=3, verbose=2,
                                   random_state=42, n_jobs=-1)
    # Fit the random search model
    mlp_random.fit(X_train, y_train)

    print(mlp_random.best_params_)

    return mlp_random.best_estimator_


def hyperopt_run(X_train, train_y, X_test, test_y):
    estim = HyperoptEstimator()
    estim.fit(X_train, train_y)
    prediction = estim.predict(X_test)
    score = estim.score(X_test, test_y)
    print(score)
    print(estim.best_model())

    return estim


def optuna_mlp_classifier(X_train, train_y, X_test, test_y):
    import optuna
    import warnings
    from sklearn.metrics import f1_score
    from sklearn.model_selection import cross_val_score, cross_val_predict
    warnings.filterwarnings('ignore')

    def objective(trial):
        params = {
            'first_layer_size': trial.suggest_int('first_layer_size', low=400, high=500),
            'second_layer_size': trial.suggest_int('second_layer_size', low=200, high=400),
            'third_layer_size': trial.suggest_int('third_layer_size', low=100, high=200),
            'fourth_layer_size': trial.suggest_int('fourth_layer_size', low=100, high=500),
            'activation': trial.suggest_categorical('activation', choices=['identity', 'logistic', 'tanh', 'relu']),
            'solver': trial.suggest_categorical('solver', choices=['lbfgs', 'sgd', 'adam']),
            'penalty': trial.suggest_categorical('penalty', choices=['elasticnet', 'l2']),
            'learning_rate': trial.suggest_categorical('learning_rate', choices=['constant', 'invscaling', 'adaptive']),
            'batch_size': trial.suggest_int('batch_size', low=100, high=200),
            'n_iter_no_change': trial.suggest_int('n_iter_no_change', low=10, high=20),
            'learning_rate_init': trial.suggest_float('learning_rate_init ', 0.0001, 0.1, step=0.005),
            'alpha': trial.suggest_float('alpha ', 0.0001, 0.1, step=0.005),
            'l1_ratio': trial.suggest_float('l1_ratio ', 0.0001, 0.1, step=0.005),
            'power_t': trial.suggest_float('power_t ', 0.0001, 0.1, step=0.005),
            'momentum': trial.suggest_float('momentum ', 0.0001, 0.1, step=0.005),
            'epsilon': trial.suggest_float('epsilon ', 0.0001, 0.1, step=0.005),
            'validation_fraction': trial.suggest_float('validation_fraction ', 0.0001, 0.1, step=0.005),
            'beta_1': trial.suggest_float('beta_1 ', 0.0001, 0.1, step=0.005),
            'beta_2': trial.suggest_float('beta_2 ', 0.0001, 0.1, step=0.005),
            'tol': trial.suggest_float('tol ', 0.0001, 0.1, step=0.005)
        }
        # params = {
        #     'learning_rate_init': trial.suggest_float('learning_rate_init ', 0.0001, 0.1, step=0.005),
        #     'first_layer_neurons': trial.suggest_int('first_layer_neurons', 10, 100, step=10),
        #     'second_layer_neurons': trial.suggest_int('second_layer_neurons', 10, 100, step=10),
        #     'activation': trial.suggest_categorical('activation', ['identity', 'tanh', 'relu']),
        # }

        model = MLPClassifier(
            hidden_layer_sizes=(params['first_layer_size'], params['second_layer_size'], params['third_layer_size']),
            learning_rate_init=params['learning_rate_init'],
            activation=params['activation'],
            solver=params['solver'],
            learning_rate=params['learning_rate'],
            batch_size=params['batch_size'],
            n_iter_no_change=params['n_iter_no_change'],
            alpha=params['alpha'],
            power_t=params['power_t'],
            momentum=params['momentum'],
            epsilon=params['epsilon'],
            validation_fraction=params['validation_fraction'],
            beta_1=params['beta_1'],
            beta_2=params['beta_2'],
            tol=params['tol'],
            random_state=1,
            max_iter=500
        )

        # score = cross_val_score(model, X_train, train_y, n_jobs=-1, cv=3)
        # return score.mean()
        model.fit(X_train, train_y)
        predicted = model.predict(X_test)
        return f1_score(test_y, predicted, average='weighted')

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=100)


def train():
    if os.path.exists("x_train.np.npy"):
        X_train = np.load("x_train.np.npy", allow_pickle=True)
        train_y = pd.read_csv("train_y.csv").iloc[:, 1]
        with open("w2v_train.pkl", "rb") as f:
            w2v_model = pickle.load(f)
        test_x = pd.DataFrame(np.load("x_test.np.npy", allow_pickle=True), columns=["imports", "path"])
        test_y = pd.read_csv("test_y.csv").iloc[:, 1]
    else:
        print("HERE!")
        train, test = train_test_split(df, test_size=0.2)
        # train, test = df, df_proxy

        train_x = train['imports']
        train_y: pd.Series = train['type']
        test_x = test[['imports', 'path']]
        test_y: pd.Series = test['type']

        print("Train value count")
        print(train["type"].value_counts())
        print("Test value count")
        print(test["type"].value_counts())

        X_train = train_x.apply(preprocess)
        # X_test = test_x.apply(preprocess)
        sentences = [sentence.split() for sentence in X_train]
        w2v_model = Word2Vec(sentences, hs=1, vector_size=100, window=5, min_count=1, workers=4, epochs=10, sg=1)
        X_train = np.array([vectorize(sentence, w2v_model) for sentence in X_train])
        # X_test = np.array([vectorize(sentence, w2v_model) for sentence in X_test])

        np.save("x_train.np", X_train)
        train_y.to_csv("train_y.csv")
        with open("w2v_train.pkl", "wb") as f:
            pickle.dump(w2v_model, f)
        np.save("x_test.np", test_x)
        test_y.to_csv("test_y.csv")

    # optuna_mlp_classifier(X_train, train_y, X_test, test_y)


    # X_train_vect_avg = []
    # for v in X_train_vect:
    #     if v.size:
    #         X_train_vect_avg.append(v.mean(axis=0))
    #     else:
    #         X_train_vect_avg.append(np.zeros(100, dtype=float))
    #
    # X_test_vect_avg = []
    # for v in X_test_vect:
    #     if v.size:
    #         X_test_vect_avg.append(v.mean(axis=0))
    #     else:
    #         X_test_vect_avg.append(np.zeros(100, dtype=float))
    model_str = "Support Vector Machine"
    # spca = SparsePCA()
    # X_train = spca.fit_transform(X_train, train_y)
    # X_test = spca.fit_transform(X_test, test_y)
    model = RandomForestClassifier(n_estimators=400, min_samples_split=10, min_samples_leaf=1, max_features='sqrt', max_depth=60, bootstrap=False)
    # model = SVC(C=600, kernel="rbf", probability=True) # kernel='rbf', tol=0.0001,
    # model = MLPClassifier(hidden_layer_sizes=(1000, 500, 300, 100))
    if False:
        Cs = [0, 0.5, 1, 4, 10, 50, 100, 500, 600, 1000, 2000]
        train_sizes = [0.7]
        labels = [f"train size fraction: {train_size}" for train_size in train_sizes]
        results = {"C": Cs}
        shuffle_params = {
            "test_size": 0.3,
            "n_splits": 3,
            "random_state": 1,
        }
        if os.path.exists("cv_c_svc.csv") and False:
            train_sizes = [0.3, 0.5, 0.7]
            labels = [f"fraction: {train_size}" for train_size in train_sizes]
            results = pd.read_csv("cv_c_svc.csv").iloc[:, 1:]
        else:
            # model_l2 = LinearSVC(penalty="l2", loss="squared_hinge", dual=True)
            for label, train_size in zip(labels, train_sizes):
                cv = ShuffleSplit(train_size=train_size, **shuffle_params)
                train_scores, test_scores = validation_curve(
                    model,
                    X_train,
                    train_y,
                    param_name="C",
                    param_range=Cs,
                    cv=cv,
                    n_jobs=-1,
                    verbose=1
                )
                results[label] = test_scores.mean(axis=1)
            results = pd.DataFrame(results)

        results.to_csv("150_samples_c_cv_svc.csv")

        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(nrows=1, ncols=1, figsize=(12, 6))

        # plot results without scaling C
        results.plot(x="C", ax=axes, logx=True)
        axes.set_ylabel("CV score")
        axes.set_title("CV tunning C parameter")

        # Set minor tick locations on the y-axis
        from matplotlib.ticker import MultipleLocator, FormatStrFormatter

        # axes.xaxis.set_minor_locator(MultipleLocator(500))
        # axes.grid(which='both', linestyle='--', linewidth=0.5)

        for label in labels:
            best_C = results.loc[results[label].idxmax(), "C"]
            axes.axvline(x=best_C, linestyle="--", color="grey", alpha=0.8)

        plt.show()
    if False:
        train_params = {
            'C': [0.1, 0.5, 1, 4, 10, 50, 100, 500, 600, 1000, 2000]
        }
        gs = GridSearchCV(model, train_params, verbose=1, cv=5)
        gs.fit(X_train, train_y)
        model = gs.best_estimator_
        print(gs.cv_results_, "\n====\n", gs.best_params_, gs.best_score_)
    # plot_grid_search(gs.cv_results_, "C", 1)
    # model = RandomForestClassifier()
    # model = MLPClassifier(hidden_layer_sizes=(1000, 500, 100, 50, 25))
    # model = tune_mlp(model, X_train, train_y)
    # train_params = {
    #     'alpha': ['log', 'hinge'],
    #     'penalty': ['elasticnet', 'l2'],
    #     'alpha': [0.0001, 0.001, 0.15],
    #     'l1_ratio': [0.0001]
    # }

    # train_params = {
    #     'kernel': ['linear', 'poly', 'rbf', 'sigmoid'],
    #     'C': [0.1, 1, 2],
    #     'tol': [0.0001, 0.001, 0.15]
    # }
    # gs = GridSearchCV(model, train_params, verbose=1)
    # gs.fit(X_train, train_y)
    # model = gs.best_estimator_
    # print(gs.cv_results_)

    # model.fit(X_train, train_y)
    # model = tune_random_forest(model, X_train, train_y)
    # y_score = model.fit(X_train, train_y)
    model.fit(X_train, train_y)

    y_pred = []
    times = []
    failed = 0
    for i, path in enumerate(test_x["path"].values):
        start_time = time()
        imports = parse_pe_imports(path)
        if imports == 'FAILED TO PARSE':
            failed += 1
            imports = test_x.loc[test_x["path"] == path]["imports"].iloc[0]
        imports = preprocess(imports)
        vectorized = np.array([vectorize(imports, w2v_model)])
        pred = model.predict(vectorized)
        times.append(time() - start_time)
        y_pred.append(pred)
    print("Total", i)
    print("Failed to parse", failed)
    print("Average time, s", np.average(times))
    print(output_metrics(test_y.values, y_pred, model_str))
    print(metrics.classification_report(test_y, y_pred, target_names=np.unique(test_y)))

    plot_roc_multiple(train_y, test_y, y_score, ["worm", "adware", "benign", "trojan"], model_str)
    # plot_learning_curve(model, f'{model_str} evaluation', X_train, train_y)

    for n_gram in N_GRAM_SELECTED:

        count_vect = CountVectorizer(ngram_range=n_gram)
        tf_idf_vectorizer = TfidfTransformer()

        X_train_counts = count_vect.fit_transform(train_x)
        X_test_counts = count_vect.transform(test_x)

        X_train_tfidf = tf_idf_vectorizer.fit_transform(X_train_counts)
        X_test_tfidf = tf_idf_vectorizer.transform(X_test_counts)

        print(train_y.value_counts())
        print(test_y.value_counts())

        # n_components = 1000
        #
        # print(
        #     "Extracting the top %d eigenfaces from %d faces" % (n_components, X_train_tfidf.shape[0])
        # )
        # svd = TruncatedSVD(n_components=n_components, n_iter=7, random_state=42)
        #
        # print("Projecting the input data on the eigenfaces orthonormal basis")
        # X_train_svd = svd.fit_transform(X_train_tfidf)
        # X_test_svd = svd.fit_transform(X_test_tfidf)

        sgd = SGDClassifier()
        sgdc_params = {
            'loss': ['log', 'hinge'],
            'penalty': ['elasticnet', 'l2'],
            'alpha': [0.0001, 0.001, 0.15],
            'l1_ratio': [0.0001]
        }
        sgdc_gs = GridSearchCV(sgd, sgdc_params, verbose=1)
        sgdc_gs.fit(X_train_tfidf, train_y)
        print(sgdc_gs.best_params_)
        print(sgdc_gs.best_score_)
        estimator = sgdc_gs.best_estimator_
        predicted = estimator.predict(X_test_tfidf)
        print(metrics.classification_report(test_y, predicted, target_names=np.unique(test_y)))

        # rfc = SGDClassifier()
        # sgdc_params = {
        #     'loss': ['log', 'hinge'],
        #     'penalty': ['elasticnet', 'l2'],
        #     'alpha': [0.0001, 0.001, 0.15],
        #     'l1_ratio': [0.0001]
        # }
        # sgdc_gs = GridSearchCV(sgd, sgdc_params, verbose=1)
        # rfc.fit(X_train_tfidf, train_y)
        # print(sgdc_gs.best_params_)
        # print(sgdc_gs.best_score_)
        # estimator = sgdc_gs.best_estimator_
        # predicted = rfc.predict(X_test_tfidf)
        print(metrics.classification_report(test_y, predicted, target_names=np.unique(test_y)))
        output_metrics(test_y, predicted, "MLP")

        plot_learning_curve(estimator, 'SGD learning curve', X_train_tfidf, train_y)
        # plot_loss_on_dataset(X_train_tfidf, train_y, "PE classification")
        # mlp = MLPClassifier(hidden_layer_sizes=(50,))
        # mlp.fit(X_train_tfidf, train_y)
        # predicted = mlp.predict(X_test_tfidf)
        # print(time.time() - start_time)
        # test_y_nums = test_y.map(lambda x: CLASSES_STR_SELECTED.index(x))
        # train_y_nums = train_y.map(lambda x: CLASSES_STR_SELECTED.index(x))


if __name__ == '__main__':
    train()
