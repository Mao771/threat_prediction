# Import required packages
#`
# beliefs = network.predict_proba({'guest': 'A'})
# beliefs = map(str, beliefs)
# print("n".join("{} t {}".format(state.name, belief) for state, belief in zip(network.states, beliefs)))
from pomegranate import *
from util import get_threats
import pandas as pd
import json
import re
from pybbn.graph.dag import Bbn
from pybbn.graph.edge import Edge, EdgeType
from pybbn.graph.jointree import EvidenceBuilder
from pybbn.graph.node import BbnNode
from pybbn.graph.variable import Variable
from pybbn.pptc.inferencecontroller import InferenceController
import warnings
from matplotlib import pyplot as plt
import networkx as nx
from pybbn.generator.bbngenerator import convert_for_drawing


class BayesianPredictor:

    def __init__(self):
        self.A = self.B = {}
        self.dag_nodes = []
        self.dag_edges = {}
        self.corr = {}
        self.cpt = None
        self.bbn = Bbn()
        self.node_id = 0

    def add_dag_node(self, detail, src, dst):
        id = self.node_id + 1
        self.node_id += 1
        self.dag_nodes.append({
            'id': id,
            'name': detail,
            'src': src,
            'dst': dst
        })

        return id

    def create_node_alerts(self, row):
        detail = row[0].replace('"', '')
        alert_data = {
            'detail': detail,
            'ip': [{
                'src': row[1],
                'dst': row[2]
            }]
        }

        if not self.A and not self.B:
            self.A = alert_data
        elif self.A and not self.B:
            if detail == self.A['detail']:
                self.A['ip'].append({
                    'src': row[1],
                    'dst': row[2]
                })
            else:
                self.B = alert_data
        elif self.A and self.B:
            if detail == self.B['detail']:
                self.B['ip'].append({
                    'src': row[1],
                    'dst': row[2]
                })
            else:
                corr_ab = {}
                corr_a_all = len(self.A['ip'])

                for a_ip in self.A['ip']:
                    for b_ip in self.B['ip']:
                        a_id = None
                        b_id = None

                        for node in self.dag_nodes:
                            if node['name'] == self.A['detail'] and node['src'] == a_ip['src'] and node['dst'] == a_ip['dst']:
                                a_id = node['id']
                            if node['name'] == self.B['detail'] and node['src'] == b_ip['src'] and node['dst'] == \
                                    b_ip['dst']:
                                b_id = node['id']

                        if a_id is None:
                            a_id = self.add_dag_node(self.A['detail'], a_ip['src'], a_ip['dst'])
                        if b_id is None:
                            b_id = self.add_dag_node(self.B['detail'], b_ip['src'], b_ip['dst'])

                        if a_ip['src'] == b_ip['src'] and a_ip['dst'] == b_ip['dst']\
                                or a_ip['dst'] == b_ip['src']:
                            if corr_ab.get(f"{a_id}/{b_id}") is None:
                                corr_ab[f"{a_id}/{b_id}"] = 1
                            else:
                                corr_ab[f"{a_id}/{b_id}"] += 1
                            break

                for key, value in corr_ab.items():
                    a_id, b_id = key.split('/')
                    for node in self.dag_nodes:
                        if node['id'] == b_id:
                            if node['probs'] is None:
                                node['probs'] = [{
                                    'id': a_id,
                                    'prob': value / corr_a_all
                                }]
                            else:
                                node['probs'].append({
                                    'id': a_id,
                                    'prob': value / corr_a_all
                                })
                            break

                # pa_b = corr_ab / len(self.A['ip'])
                # if self.node_id < 10:
                #     node_a = BbnNode(
                #         Variable(
                #             self.node_id,
                #             self.A['detail'],
                #             self.B['detail']),
                #         [1]
                #     )
                #     node_b = BbnNode(
                #         Variable(
                #             self.node_id + 1,
                #             self.B['detail'],
                #             self.A['detail']),
                #         [pa_b]
                #     )
                #     self.node_id += 2
                #     self.bbn.add_node(node_a).add_node(node_b).add_edge(Edge(node_a, node_b, EdgeType.DIRECTED))
                # hyperattack_name = f"{self.A['detail']}/{self.B['detail']}"
                #self.corr.append({'name': hyperattack_name,
                #                  'corr': pa_b})
                # self.corr[hyperattack_name] = max(self.corr.get(hyperattack_name) or 0, corr_ab / len(self.A['ip']))

                self.A = self.B
                self.B = alert_data

    def process_alerts(self):
        df_threats = get_threats()
        # df_threats.to_csv('threats.csv')
        [self.create_node_alerts(row) for row in df_threats[['detail', 'source', 'destination', 'severity']].values]

        result = json.dumps(self.dag_nodes)
        print(result)

    def draw_bbn(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')

            graph = convert_for_drawing(self.bbn)
            pos = nx.nx_agraph.graphviz_layout(graph, prog='neato')
        plt.figure(figsize=(20, 10))
        plt.subplot(121)
        labels = dict([(k, node.variable.name) for k, node in self.bbn.nodes.items()])
        nx.draw(graph, pos=pos, with_labels=True, labels=labels)
        plt.title('BBN DAG')
        plt.show()

    def create_cpt(self):
        dag_node_values = {}
        dag_nodes = {}
        for key, value in self.corr.items():
            attack_in, attack_out = key.split('/')
            if not dag_node_values.get(attack_in):
                dag_node_values[attack_in] = {
                    attack_out: value
                }
            else:
                dag_node_values[attack_in][attack_out] = value

        id = 0
        for key, value in dag_node_values.items():
            dag_nodes[key] = BbnNode(
                Variable(
                    id,
                    key,
                    [attack_key for attack_key in dag_node_values.keys()]),
                [attack_p for attack_p in dag_node_values.values()]
            )


if __name__ == '__main__':
    df_threats = get_threats(days=3)
    df_threats.to_csv('threats.csv')
    bp = BayesianPredictor()
    bp.process_alerts()
    #bp.draw_bbn()
    # bp.create_cpt()
    # dt = pd.to_datetime(df_threats.time)
    # for i, j in df_threats.groupby([(dt - dt[0]).astype('timedelta64[h]')]):
    #     df_batch = j.reset_index(drop=True)
    #     print(df_batch)
    # df_grouped = df_threats.groupby(['destination', 'source', 'severity', 'detail']).count() # size().div(len(df_threats)
    # json_grouped = df_threats.groupby(([df_threats.detail != df_threats.detail.shift()])\
    #     .apply(lambda x: x.to_json(orient='records'))
    # result = df_grouped.to_json()
    # print(json_grouped)

    # from matplotlib import pyplot as plt
    # from pomegranate import *
    #
    # guest = DiscreteDistribution({'A': 1. / 3, 'B': 1. / 3, 'C': 1. / 3})
    # prize = DiscreteDistribution({'A': 1. / 3, 'B': 1. / 3, 'C': 1. / 3})
    # monty = ConditionalProbabilityTable(
    #     [['A', 'A', 'A', 0.0],
    #      ['A', 'A', 'B', 0.5],
    #      ['A', 'A', 'C', 0.5],
    #      ['A', 'B', 'A', 0.0],
    #      ['A', 'B', 'B', 0.0],
    #      ['A', 'B', 'C', 1.0],
    #      ['A', 'C', 'A', 0.0],
    #      ['A', 'C', 'B', 1.0],
    #      ['A', 'C', 'C', 0.0],
    #      ['B', 'A', 'A', 0.0],
    #      ['B', 'A', 'B', 0.0],
    #      ['B', 'A', 'C', 1.0],
    #      ['B', 'B', 'A', 0.5],
    #      ['B', 'B', 'B', 0.0],
    #      ['B', 'B', 'C', 0.5],
    #      ['B', 'C', 'A', 1.0],
    #      ['B', 'C', 'B', 0.0],
    #      ['B', 'C', 'C', 0.0],
    #      ['C', 'A', 'A', 0.0],
    #      ['C', 'A', 'B', 1.0],
    #      ['C', 'A', 'C', 0.0],
    #      ['C', 'B', 'A', 1.0],
    #      ['C', 'B', 'B', 0.0],
    #      ['C', 'B', 'C', 0.0],
    #      ['C', 'C', 'A', 0.5],
    #      ['C', 'C', 'B', 0.5],
    #      ['C', 'C', 'C', 0.0]], [guest, prize])
    #
    # d1 = State(guest, name="guest")
    # d2 = State(prize, name="prize")
    # d3 = State(monty, name="monty")
    #
    # network = BayesianNetwork("Solving the Monty Hall Problem With Bayesian Networks")
    # network.add_states(d1, d2, d3)
    # network.add_edge(d1, d3)
    # network.add_edge(d2, d3)
    # network.bake()
    # network.plot('test')
    # plt.show()
