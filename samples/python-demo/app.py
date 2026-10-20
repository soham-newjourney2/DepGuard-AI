import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/import")
def import_config():
    config = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(config)


@app.get("/proxy")
def proxy():
    return requests.get(request.args["url"], timeout=5).text
