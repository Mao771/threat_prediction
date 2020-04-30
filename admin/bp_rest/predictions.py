from flask import Blueprint, request, jsonify
from datetime import datetime
from random import random

predictions = Blueprint('predictions', __name__, template_folder='templates', static_folder='static')


@predictions.route('/threats', methods=['GET'])
def threats():
    dt_start = request.form.get('dtStart') or request.args.get('dtStart')
    dt_end = request.form.get('dtEnd') or request.args.get('dtEnd')
    # sensor = request.form.get('sensor') or request.args.get('sensor')
    #
    # dt_start = datetime.strptime(dt_start, '%Y-%m-%d')
    # dt_end = datetime.strptime(dt_end, '%Y-%m-%d')

    udp_flood = []
    tcp_flood = []
    other = []

    for _ in range(100):
        udp_flood.append(random() * 10 / 2)
        tcp_flood.append(random() * 10 / 2)
        other.append(random() * 10 / 2)

    return jsonify({'udp_flood': udp_flood, 'tcp_flood': tcp_flood, 'other': other}), 200


@predictions.route('/add', methods=['POST'])
def climate_add():
    try:
        return '', 200
    except Exception as e:
        return jsonify({'error': str(e)}), 501
