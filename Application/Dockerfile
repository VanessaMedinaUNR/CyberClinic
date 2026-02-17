FROM mcr.microsoft.com/windows:ltsc2019 AS win_builder

#ADD https://www.python.org/ftp/python/3.14.0/python-3.14.0-amd64.exe C:/python3.exe
#RUN c:\python3.exe /quiet InstallAllUsers=1 PrependPath=1
#RUN del c:\python3.exe -Force

#WORKDIR /shared
#COPY requirements.txt requirements.txt

#RUN pip install --upgrade pip
#RUN pip install -r requirements.txt


FROM python:3.14 AS linux_builder

RUN apt update && \
  apt install libgl1 libxkbcommon-x11-0 libegl1 dbus -y && \
  apt upgrade -y
RUN pip install --upgrade pip

WORKDIR /src
COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt


FROM dockurr/macos AS mac_builder

ARG VERSION
ENV RELEASE="python-3.13.9-macos${VERSION}.pkg"

RUN curl -O https://www.python.org/ftp/python/3.13.9/${RELEASE}

RUN sudo installer -pkg ./${RELEASE} -target /
RUN /usr/local/bin/python3 -m ensurepip --upgrade

WORKDIR /src

RUN pip install -r requirements.txt
CMD ["pyinstaller", \ 
    "--distpath /dist/macos", \
    "-n CyberClinic", \
    "client_application.py"]