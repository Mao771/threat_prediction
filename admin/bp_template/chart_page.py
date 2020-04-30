from flask import Blueprint, render_template, abort
from flask_login import login_required

from jinja2 import TemplateNotFound

chart = Blueprint('chart', __name__, template_folder='templates', static_folder='static')


@chart.route('/chart')
@login_required
def render_chart():
    try:
        return render_template('charts.html',
                               sensors=[],
                               measurement={})
    except TemplateNotFound:
        abort(404)
