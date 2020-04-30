from flask import Blueprint, render_template, abort
from flask_login import login_required

from jinja2 import TemplateNotFound

index = Blueprint('index', __name__, template_folder='templates', static_folder='static')


@index.route('/')
@login_required
def render():
    try:
        return render_template('charts.html',
                               sensors=[],
                               measurement={})
    except TemplateNotFound:
        abort(404)
