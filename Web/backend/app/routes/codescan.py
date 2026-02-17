from flask import Flask, request, jsonify
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  

OLLAMA_URL = "http://localhost:11434/api/generate"

@app.route("/codescan", methods=["POST"])
def scan_code():
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
    app.run(port=5000, debug=True)
