from flask import Blueprint, request, jsonify
import requests

codescan_bp = Blueprint("codescan", __name__)

OLLAMA_URL = "http://ollama:11434/api/generate"

def generate_prompt(user_code):
    return f"""
Analyze the following code for:
- Security vulnerabilities
- Syntax errors
- Suggestions for improvement

Code:
{user_code}
"""

@codescan_bp.route("/api/codescan", methods=["POST"])
def code_scan():
    data = request.get_json()
    user_code = data.get("code")

    if not user_code:
        return jsonify({"error": "No code provided"}), 400

    prompt = generate_prompt(user_code)

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": "deepseek-coder",
            "prompt": prompt,
            "stream": False
        }
    )

    result = response.json()

    return jsonify({"analysis": result.get("response", "No response")})