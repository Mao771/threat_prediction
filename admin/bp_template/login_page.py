from flask import Blueprint, render_template, abort, request, redirect, url_for
from flask_login import login_user, current_user
from jinja2 import TemplateNotFound
from admin.models import User

login = Blueprint('login', __name__, template_folder='templates', static_folder='static')


@login.route('/login')
def render_login():
    try:
        if current_user.is_authenticated:
            return redirect(url_for('search.render_search'))
        return render_template('login.html')
    except TemplateNotFound:
        abort(404)


@login.route('/auth')
def auth():
    login = request.form.get('login') or request.args.get('login')
    password = request.form.get('password') or request.args.get('password')

    user = User.query.filter_by(login=login).first()
    # TODO CHECK BY HASH
    # TODO FLASK MESSAGES
    if not user or not user.password == password:
        return redirect(url_for('login.render_login'))
    login_user(user, remember=True)
    return redirect(url_for('chart.render_chart'))
