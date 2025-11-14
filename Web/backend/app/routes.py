from flask import jsonify, request
from app import app

@app.route('/')
@app.route('/index', methods = ['GET'])
def index():
    data = "Hello World"
    return jsonify({'data': data})