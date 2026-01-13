FROM python:3.14.0 AS win_builder

#RUN pip install --upgrade pip

WORKDIR c:\\shared
COPY requirements.txt requirements.txt

#RUN pip install -r requirements.txt
#CMD ["pyinstaller", \ 
#    "--distpath C:\\dist\\windows", \
#    "-n CyberClinic", \
#    "--noconfirm", \
#    "client_application.py"]


FROM python:3.14.0 AS linux_builder

RUN apt update && \
  apt install libgl1 libxkbcommon-x11-0 libegl1 dbus -y && \
  apt upgrade -y
RUN pip install --upgrade pip

WORKDIR /src
COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt


FROM dockurr/macos AS mac_builder

ENV RELEASE="python-3.13.9-macos11.pkg"

RUN curl -O https://www.python.org/ftp/python/3.13.9/${RELEASE}

RUN sudo installer -pkg ./${RELEASE} -target /
RUN /usr/local/bin/python3 -m ensurepip --upgrade

WORKDIR /src

RUN pip install -r requirements.txt
CMD ["pyinstaller", \ 
    "--distpath /dist/macos", \
    "-n CyberClinic", \
    "client_application.py"]