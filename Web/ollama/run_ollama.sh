#!/usr/bin/env bash
ollama serve &
SERVER_PID=$!

echo "Waiting for Ollama server to be active..."
while [ "$(ollama list | grep 'NAME')" == "" ]; do
  sleep 1
done

ollama pull deepseek-coder:1.3b
echo "Ollama server is active and model is pulled. Server PID: $SERVER_PID"
wait $SERVER_PID