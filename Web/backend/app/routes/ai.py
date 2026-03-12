from flask import Blueprint, Flask, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
import logging
from ollama import Client
import os


host = os.environ.get('OLLAMA_HOST', 'localhost')
port = os.environ.get('OLLAMA_PORT', 11434)
client = Client(f"http://{host}:{port}")

logger = logging.getLogger(__name__)

ai_bp = Blueprint('ai', __name__, url_prefix='/api/ai')

SERVER_PROMPT = """You are a helpful assistant for analyzing code.
You will be given a piece of code and you should analyze it for security vulnerabilities, syntax errors, and suggestions for improvement.
Provide a detailed analysis of the code, including any potential issues and how to fix them.
Be thorough and provide examples if necessary."""

def generate_prompt(user_code):
    return f"""
    {SERVER_PROMPT}
    Please analyze the following code for:
    - Security vulnerabilities
    - Syntax errors
    - Suggestions for improvement

    Code:
    {user_code}
    """

@jwt_required()
@ai_bp.route("/codescan", methods=["POST"])
def code_scan():
    data = request.get_json()
    logger.debug(f"Received data for code scan: {data}")
    user_code = data["code"]

    logger.debug(f"Received code for analysis: {user_code[:100]}...")  # Log the first 100 characters of the code

    prompt = generate_prompt(user_code)

    response = client.generate(
        model = "deepseek-coder:1.3b",
        prompt = prompt,
        stream = False
    )

    result = response

    return jsonify({"analysis": result["response"]})

