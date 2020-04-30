from flask import Flask, render_template, request
import os


app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))


@app.route('/')
def index():
    return render_template('index.html')
