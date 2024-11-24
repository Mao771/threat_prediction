from util import get_threats
import pandas as pd
import json
from pybbn.graph.dag import Bbn
from pybbn.graph.edge import Edge, EdgeType
from pybbn.graph.node import BbnNode
from pybbn.graph.variable import Variable
from pybbn.graph.jointree import EvidenceBuilder
from pybbn.pptc.inferencecontroller import InferenceController
import warnings
from matplotlib import pyplot as plt
import networkx as nx
from pybbn.generator.bbngenerator import convert_for_drawing
from typing import List
from util import DbHelper
from definitions import SETTINGS_FILE
import datetime
from itertools import product
import sys
import threading

import matplotlib
matplotlib.use('TkAgg')


class BayesianPredictor:

    def __init__(self, df_alerts: pd.DataFrame):
        self.df_alerts = df_alerts
        self.A = self.B = {}
        self.dag_nodes = {}
        self.bbn_nodes = {}
        self.dag_edges = {}
        self.corr = {}
        self.cpt = None
        self.bbn = Bbn()
        self.bbn_pmg_nodes = {}
        self.node_id = 0

    def add_dag_node(self, detail, src, dst):
        dag_id = self.node_id + 1
        self.node_id += 1
        self.dag_nodes[dag_id] = {
            'name': detail,
            'src': src,
            'dst': dst
        }

        return dag_id

    def add_bbn_node(self, node_id, name, prob_names: List[str], prob_values: List[float]):
        self.bbn_nodes[node_id] = BbnNode(
            Variable(
                node_id,
                name,
                prob_names
            ),
            prob_values
        )

        return self.bbn_nodes[node_id]

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

                        for dag_id, node in self.dag_nodes.items():
                            if node['name'] == self.A['detail'] and node['src'] == a_ip['src'] and node['dst'] == \
                                    a_ip['dst']:
                                a_id = dag_id
                            if node['name'] == self.B['detail'] and node['src'] == b_ip['src'] and node['dst'] == \
                                    b_ip['dst']:
                                b_id = dag_id

                        if a_id is None:
                            a_id = self.add_dag_node(self.A['detail'], a_ip['src'], a_ip['dst'])
                        if b_id is None:
                            b_id = self.add_dag_node(self.B['detail'], b_ip['src'], b_ip['dst'])

                        if a_ip['src'] == b_ip['src'] and a_ip['dst'] == b_ip['dst'] \
                                or a_ip['dst'] == b_ip['src']:
                            if corr_ab.get(f"{a_id}/{b_id}") is None:
                                corr_ab[f"{a_id}/{b_id}"] = 1
                            else:
                                corr_ab[f"{a_id}/{b_id}"] += 1
                            break

                for key, value in corr_ab.items():
                    a_id, b_id = key.split('/')
                    for dag_id, node in self.dag_nodes.items():
                        if int(dag_id) == int(b_id):
                            if node.get('probs') is not None:
                                try:
                                    node['probs'][int(a_id)] = min(node['probs'][int(a_id)], value / corr_a_all)
                                except KeyError:
                                    node['probs'][int(a_id)] = value / corr_a_all
                            else:
                                node['probs'] = {
                                    int(a_id): value / corr_a_all
                                }
                            break

                self.A = self.B
                self.B = alert_data

    def process_dag_nodes(self):
        result_dag_nodes = {}

        for dag_id, node in self.dag_nodes.items():
            node_probs = node.get('probs')
            if node_probs is not None:
                # detecting and removing cycles
                for dag_prob_id, node_prob in node_probs.items():
                    dag_prob_probs = self.dag_nodes[int(dag_prob_id)].get('probs')
                    if dag_prob_probs is not None and dag_prob_probs.get(int(dag_id)) is not None:
                        dag_prob_probs.pop(int(dag_id), None)

                result_dag_nodes[dag_id] = node
            else:
                for idj, nodej in self.dag_nodes.items():
                    try:
                        if int(dag_id) in nodej['probs'].keys():
                            result_dag_nodes[dag_id] = node
                    except KeyError:
                        continue

        return result_dag_nodes

    def _process_alerts(self):
        print('Creating correlated threats alerts...')

        [self.create_node_alerts(row) for row in self.df_alerts[['detail', 'source', 'destination', 'severity']].values]

    def build_bbn(self):
        self._process_alerts()

        print('Building Bayesian network of threats...')

        processed_dag_nodes = self.process_dag_nodes()

        for dag_id, node in processed_dag_nodes.items():
            prob_values = []
            prob_names = [f'Occurs', f'Does not occur']

            if node.get('probs') is not None and len(node.get('probs')) > 0:
                cpt_states = set(product(['Occurs', 'Does not occur'], repeat=len(node.get('probs'))))

                for cpt_state in cpt_states:
                    prob_occur = False
                    for idx, node_id in enumerate(node.get('probs')):
                        if cpt_state[idx] != 'Does not occur':
                            prob_occur = True
                            prob = node.get('probs')[node_id]
                            if prob == 1:
                                prob = 0.99
                            prob_values.extend([prob, 1 - prob])
                            break
                    if not prob_occur:
                        prob_values.extend([0, 0])

                # for node_id, prob_val in node.get('probs').items():
                #     prob_values.extend([prob_val, 1-prob_val, 0.5, 0.5])
            else:
                prob_values = [0.5, 0.5]
            nl = '\n'
            self.bbn.add_node(self.add_bbn_node(dag_id, f"{node['name']}{nl}{node['src']}->{node['dst']}", prob_names,
                                                prob_values))

        for dag_id, node in processed_dag_nodes.items():
            try:
                for node_id, _ in node['probs'].items():
                    self.bbn.add_edge(Edge(
                        self.bbn_nodes[int(node_id)],
                        self.bbn_nodes[int(dag_id)],
                        EdgeType.DIRECTED
                    ))
            except KeyError:
                continue

    def draw_bbn(self):
        print("Drawing Bayesian network of threats...")
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')

            graph = convert_for_drawing(self.bbn)
            pos = nx.nx_agraph.graphviz_layout(graph, prog='neato')
        plt.figure(figsize=(20, 10))
        plt.subplot(121)
        labels = dict([(k, node.variable.name) for k, node in self.bbn.nodes.items()])
        nx.draw(graph, pos=pos, with_labels=True, labels=labels)
        plt.pause(0.001)
        plt.title('Bayesian attack graph')
        plt.show()

    def make_predictions(self):
        print("Making predictions about threats level based on built Bayesian network...")

        result = []
        join_tree = InferenceController.apply(self.bbn)

        ev = EvidenceBuilder() \
            .with_node(join_tree.get_bbn_node(13)) \
            .with_evidence('Occurs', 1) \
            .build()
        join_tree.set_observation(ev)

        for node in join_tree.get_bbn_nodes():
            potential = join_tree.get_bbn_potential(node)
            node_name = node.variable.name
            occur_percent = 99 if node.id != 13 and potential.entries[0].value == 1 else potential.entries[0].value * 100
            not_occur_percent = 1 if node.id != 13 and potential.entries[1].value == 0 else potential.entries[1].value * 100
            print(node)
            print(f'Probability Occurs: {round(occur_percent)}%')
            print(f'Probability Does not occur: {round(not_occur_percent)}%')
            print('--------------------->')

            result.append({
                'measurement': 'threats_level',
                'fields': {
                    node_name: occur_percent
                }
            })

        return result


class ThreatsPredictor():

    def predict(self):
        print("-----------------------------------------------------------------------")
        print("------------Predicting threats level using Bayesian network------------")
        print("-----------------------------------------------------------------------")

        is_args = False
        args = dict(arg.split('=') for arg in sys.argv[1:])

        try:
            if is_args:
                days = int(args['days'])
            else:
                days = 7
        except Exception:
            print('Function requires a mandatory int argument that represents analyzing horizon in days: days=<days>')
        else:
            db = DbHelper(SETTINGS_FILE)

            df_threats = get_threats(days=days, from_begin=True)
            df_threats = df_threats[df_threats['type'] != 'Not Suspicious Traffic']
            df_threats.to_csv('threats.csv')
            bp = BayesianPredictor(df_threats)
            bp.build_bbn()
            bp.draw_bbn()

            result_points = bp.make_predictions()

            print("Writing results to the database")
            db.drop('threats_level')
            db.write(result_points, time_precision='ms')
            db.close()


if __name__ == '__main__':
    tp = ThreatsPredictor()
    tp.predict()
