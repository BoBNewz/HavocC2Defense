FROM python:3.12-slim

RUN apt update && apt install -y curl tshark && mkdir /havoc

WORKDIR /havoc

RUN pip install pyshark pycryptodome && curl -o havoc-http-parser.py https://raw.githubusercontent.com/BoBNewz/HavocC2Defense/refs/heads/main/Havoc_HTTP_Parser/havoc-http-parser.py

ENTRYPOINT ["python", "havoc-http-parser.py"]
