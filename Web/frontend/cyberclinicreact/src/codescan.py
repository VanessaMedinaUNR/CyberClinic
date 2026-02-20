from flask import Flask, request, jsonify
import requests
from flask_cors import CORS

app = Flask(__name__)

CORS(app, resources={r"/codescan": {"origins": "http://localhost:3000"}})

OLLAMA_URL = "http://localhost:11434/api/generate"

@app.route("/codescan", methods=["POST", "OPTIONS"])
def code_scan():
    if request.method== "OPTIONS":
        return "", 200
    data = request.get_json()
    user_code = data.get("code")

    prompt = f"""
    Analyze the following code for:
    - Security vulnerabilities
    - Syntax errors
    - Suggestions for improvement

    Code:
    {user_code}
    """

    response = requests.post(OLLAMA_URL, json={
        "model": "deepseek-coder",
        "prompt": prompt,
        "stream": False
    })

    result = response.json()

    return jsonify({"analysis": result["response"]})


if __name__ == "__main__":
    app.run(host="localhost", port=4000, debug=True)
