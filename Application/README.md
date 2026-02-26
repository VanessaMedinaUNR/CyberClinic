# Testing
```bash
python3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

pytest tests/unit # Run Unit Tests
```

# Building For Windows
```bash
python3 -m venv .venv
.venv\Scripts\activate

cp ../Web/auth.crt ./src/config

pip install -r requirements.txt
cd src
pyinstaller \
    -n CyberClinic \
    --distpath \\dist\\windows \
    --add-data 'config/*:config' \
    --add-data 'nmap-7.98-setup.exe' \
    --add-data 'tools/nikto-main/*:tools/nikto-main' \
    --onefile \
    --noconsole \
    --noconfirm \
    client_application.py
```
**Development Note:** Windows build can only be completed on a Windows host machine

# Building For Linux
```bash
cp ../Web/auth.crt ./src/config

docker-compose up -d --build 'build_linux'
```