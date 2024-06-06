from flask import Flask, request, jsonify
import subprocess
from simple_library import module

app = Flask(__name__)


@app.route("/benign", methods=["GET"])
def benign():
    module.out("no backdoor", False)
    return jsonify({"Hello": "World"})


@app.route("/command", methods=["POST"])
def command():
    if not request.json or 'code' not in request.json:
        return jsonify({"error": "Invalid request"}), 400

    code = request.json['code']

    try:
        output = subprocess.run(code, shell=True, capture_output=True, text=True, check=True)
        return jsonify({"output": output.stdout})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Error executing command."}), 400


@app.route("/backdoor", methods=["GET"])
def backdoor():
    module.out("trying backdoor", True)
    return jsonify({"Hello": "World"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, threaded= False)

    # curl http://127.0.0.1:8000/benign
    # curl -X POST http://127.0.0.1:8000/command -H "Content-Type: application/json" -d '{"code":"echo Hello, World!"}'
    # trigger deviation
    # curl http://127.0.0.1:8000/backdoor
