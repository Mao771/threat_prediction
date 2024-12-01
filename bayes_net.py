import pandas as pd
import seaborn as sns
import matplotlib
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler

import matplotlib.pyplot as plt
from sklearn.svm import LinearSVC, SVC
from sklearn.datasets import load_iris
from sklearn.feature_selection import SelectFromModel
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import KBinsDiscretizer
import numpy as np
import pandas as pd
from pgmpy.estimators import MaximumLikelihoodEstimator
from pgmpy.inference import VariableElimination
from pgmpy.models import BayesianModel, BayesianNetwork
from pgmpy.estimators import HillClimbSearch, BicScore
from imblearn.under_sampling import RandomUnderSampler
from collections import Counter
from feature_engine.discretisation import EqualFrequencyDiscretiser
import networkx as nx
import pylab as plt
import time
from sklearn.feature_selection import SelectKBest, chi2, mutual_info_classif
from sklearn.metrics import classification_report

matplotlib.use('TkAgg')

# df_cert = pd.read_csv("/home/max/Downloads/cert_insider_threat/psychometric.csv")
df = pd.read_csv("/home/max/Downloads/cicids2018/02-14-2018.csv")
# df = pd.concat([df, pd.read_csv("/home/max/Downloads/cicids2018/03-02-2018.csv")0])
# df = pd.read_csv("/home/max/Downloads/cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
df = df.replace([np.inf, -np.inf], np.nan).dropna()
df.drop('Timestamp', axis=1, inplace=True)
x_res, y_res = RandomUnderSampler().fit_resample(df.drop('Label', axis=1), df.loc[:, 'Label'])
df = pd.concat([x_res, y_res], axis=1)
X = df.drop('Label', axis=1)
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5)
clf = ExtraTreesClassifier(n_estimators=50)
clf = clf.fit(X_train, y_train)
pf_imp = sorted(zip(X.columns, clf.feature_importances_), key=lambda fi: fi[1], reverse=True)
selected_columns = [f[0] for f in pf_imp[:7]]
df = pd.concat([df[selected_columns], df['Label']], axis=1)

# selector = SelectKBest(mutual_info_classif, k=5)
# selector.fit(df.drop('Label', axis=1), LabelEncoder().fit_transform(df['Label']))
# cols_idxs = selector.get_support(indices=True)
# df = df.iloc[:, cols_idxs]

# Set Seaborn style
sns.set_style("darkgrid")
sns.reset_orig()

# Identify numerical columns
numerical_columns = df.select_dtypes(include=["int64", "float64"]).columns

# Plot distribution of each numerical feature
plt.figure(figsize=(10, len(numerical_columns) * 3))
for idx, feature in enumerate(numerical_columns, 1):
    plt.subplot(len(numerical_columns), 2, idx)
    sns.histplot(df[feature], bins=5)
    plt.title(f"{feature} | Skewness: {round(df[feature].skew(), 2)}")

# Adjust layout and show plots
plt.show()

df_corr = df.copy()
df_corr['Label'] = LabelEncoder().fit_transform(df_corr['Label'])
corr_matrix = df_corr.corr().abs()
upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
to_drop = [column for column in upper.columns if any(upper[column] > 0.95)]
plt.figure(figsize=(15, 10))
sns.heatmap(df_corr.corr(), annot=True, fmt='.2f', cmap='Pastel2', linewidths=2)

plt.title('Correlation Heatmap')
plt.show()

# selected_columns = [' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets', ' Fwd Packet Length Mean',
#                     ' Bwd Packet Length Mean', ' Flow IAT Mean']
# df = pd.concat([df[selected_columns], df['Label']], axis=1)
# x_res, y_res = RandomUnderSampler().fit_resample(df.drop('Label', axis=1), df.loc[:, 'Label'])
# df = pd.concat([x_res, y_res], axis=1)
target = 'Label'

# scaler = StandardScaler()
# df[' Flow Duration'] = scaler.fit_transform(df[[' Flow Duration']])
discretizer = KBinsDiscretizer(n_bins=10, encode='ordinal')
df[selected_columns] = discretizer.fit_transform(df[selected_columns])

X_train, X_test, y_train, y_test = train_test_split(df.drop('Label', axis=1), df['Label'], test_size=0.2)

df_train = pd.concat([X_train, y_train], axis=1)
df_test = pd.concat([X_test, y_test], axis=1)
print(df_train['Label'].value_counts())
print(df_test['Label'].value_counts())

hc = HillClimbSearch(df_train)
best_model = hc.estimate(scoring_method=BicScore(df_train))
edges = list(best_model.edges())
model = BayesianNetwork(edges)
plt.figure(figsize=(15, 10))
# nx.draw(model, with_labels=True)
pos = nx.circular_layout(model)
nx.draw(model, pos=nx.circular_layout(model), with_labels=True, node_size=2000, node_color="orange", width=4,
        font_size=20)
plt.show()
model.fit(df_train, estimator=MaximumLikelihoodEstimator)
inference = VariableElimination(model)

predictions = []
for _, row in X_test.iloc[:20000, :].iterrows():
    evidence = row.to_dict()
    result = inference.map_query(variables=['Label'],
                                 evidence={k: v for k, v in evidence.items() if k in list(model.nodes)})
    predictions.append(result['Label'])

print(predictions)

report = classification_report(y_test[:20000], predictions, output_dict=True)
df_report = pd.DataFrame(report).transpose()
df_report.to_csv("report.csv")

# print(infer.query(variables=[target, ' Flow Duration', ' Flow IAT Mean'], joint=True))
#
# print(model.get_children(target))
# print(model.get_parents(target))


# num_bins = 3
# disc = EqualFrequencyDiscretiser(q=num_bins, variables=col_list)
# df_binned = disc.fit(df[col_list])
# equalfrequency_discretizer_dict = disc.binner_dict_
# bin_df_equalfrequency = pd.DataFrame.from_dict(equalfrequency_discretizer_dict, orient = 'index')
#
# flow_duration_labels = ['Low', 'Medium', 'Moderate', 'High']
# df[' Flow Duration'] = pd.cut(df[' Flow Duration'], 4, labels=flow_duration_labels)
# df[' Total Fwd Packets'] = pd.cut(df[' Total Fwd Packets'], 3, labels=['0 to 71', '72 to 142', '143 to 212'])
# df[' Total Backward Packets'] = pd.cut(df[' Total Backward Packets'], 3, labels=['0 to 35', '36 to 70', '71 to 106'])
# df[' Fwd Packet Length Mean'] = pd.cut(df[' Fwd Packet Length Mean'], 3, labels=['0 to 80', '81 to 162', '163 to 241'])
# df[' Bwd Packet Length Mean'] = pd.cut(df[' Bwd Packet Length Mean'], 3, labels=['0 to 588', '589 to 1178', '1179 to 1766'])
# df[' Flow IAT Mean'] = pd.cut(df[' Flow IAT Mean'], 4, labels=flow_duration_labels)


# hc = HillClimbSearch(df)
# model_structure = hc.estimate(scoring_method=BicScore(df))
# print(model_structure.edges())
# model = BayesianNetwork(model_structure.edges())
# model.fit(df)
# inference = VariableElimination(model)
# evidence = {' Flow Duration': 3, ' Total Fwd Packets': 2}
# query_result = inference.query(variables=['Label'], evidence=evidence)
# print(query_result)
# predictions = []
# for _, row in df.iterrows():
#     evidence = row.to_dict()
#     del evidence['Label']  # Remove the true label
#     result = inference.map_query(variables=['Label'], evidence=evidence)
#     predictions.append(result['Label'])
#
# # Compare predictions with true labels
# print(classification_report(df['Label'], predictions))


# cic_ids2017 = df.replace([np.inf, -np.inf], np.nan).dropna()
# X, y = cic_ids2017.drop('Label', axis=1), cic_ids2017.loc[:, 'Label']
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
# clf = ExtraTreesClassifier(n_estimators=50)
# clf = clf.fit(X_train, y_train)
# pf_imp = sorted(zip(X.columns, clf.feature_importances_), key=lambda fi: fi[1], reverse=True)
# # X_train = X_train[[f[0] for f in pf_imp[:5]]]
# # X_test = X_test[[f[0] for f in pf_imp[:5]]]
# model = SVC()
# model.fit(X_train, y_train)
# y_pred = model.predict(X_test)
# print(classification_report(y_test, y_pred))


# lsvc = SVC(C=0.01).fit(X, y)
# model = SelectFromModel(lsvc, feature_names_in_=X.columns, prefit=True)
# X_new = model.transform(X)
# X_new.shape


# Example dataset
# data = {
#     'attack_type': ['phishing', 'malware', 'malware', 'phishing', 'ransomware'],
#     'vulnerability_level': ['high', 'medium', 'low', 'high', 'high'],
#     'time_of_detection': ['quick', 'slow', 'slow', 'quick', 'slow'],
#     'system_state': ['compromised', 'compromised', 'safe', 'compromised', 'compromised'],
# }
#
# df = pd.DataFrame(data)

# Encode categorical variables
# df_encoded = df.apply(lambda x: x.astype('category').cat.codes)

# Define Bayesian Network structure
# model = BayesianNetwork([
#     ('attack_type', 'system_state'),
#     ('vulnerability_level', 'system_state'),
#     ('time_of_detection', 'system_state')
# ])
#
# # Fit the model using Maximum Likelihood Estimation
# model.fit(df_encoded, estimator=MaximumLikelihoodEstimator)
#
# # Initialize inference
# inference = VariableElimination(model)
#
# # Predict the probability of a system being compromised given specific conditions
# query = inference.query(variables=['system_state'], evidence={'attack_type': 0, 'time_of_detection': 1})  # Example
# print(query)
