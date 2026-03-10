FROM ollama/ollama:latest

COPY run_ollama.sh /run_ollama.sh

RUN apt update && apt install -y \
curl \
dos2unix \
&& rm -rf /var/lib/apt/lists/*

RUN dos2unix /run_ollama.sh && \
    chmod +x /run_ollama.sh

ENTRYPOINT [ "./run_ollama.sh" ]