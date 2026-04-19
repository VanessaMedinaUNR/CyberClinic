# Building For Windows
```powershell
python3 -m venv .venv
.venv\Scripts\activate

cp ../Web/auth.crt ./src/config

pip install -r requirements.txt
cd src

pyinstaller `
-n CyberClinic `
--distpath ..\\dist\\windows `
--add-data 'config/auth.crt:config' `
--add-data 'tools/nmap-7.98-setup.exe:tools' `
--icon 'CyberClinic.ico'`
--onefile `
--noconsole `
--noconfirm `
client_application.py
```
> **Development Note:** Windows build can only be completed on a Windows host machine

# Building For Linux
```bash
cp ../Web/auth.crt ./src/config

docker-compose up -d --build 'build_linux'
```
# Testing
```bash
python3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

pytest tests/unit # Run Unit Tests
```

# License
```
Copyright (C) 2026  Austin Finch

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

See <https://www.gnu.org/licenses/> for full license terms.
```