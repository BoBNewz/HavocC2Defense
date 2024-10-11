# How to use havoc-http-parser ?

## Using a Python environment

```
git clone https://github.com/BoBNewz/HavocC2Defense.git
cd Havoc_HTTP_Parser
python -m venv havoc_env
source havoc_env/bin/activate

pip install pyshark pycryptodome
sudo apt install tshark

python havoc-http-parser.py -h
```

## Using Docker

```
git clone https://github.com/BoBNewz/HavocC2Defense.git
cd Havoc_HTTP_Parser/Docker

docker build . -t havoc-http-parser
mkdir files && mv /files/to/pcap/file.pcap files
docker --rm -v $(pwd)/files:/tmp -v $(pwd)/__output:/havoc/__output havoc-http-parser -h
```
