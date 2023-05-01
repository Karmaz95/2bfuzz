# 2Bfuzz
## DESCRIPTION
`2Bfuzz` is a Python script that provides a `TCP fuzzer` and a `payload generator`. 
* The script allows you to fuzz a server by sending a series of payloads over a TCP connection to the target IP and port.
* It also allows you to generate payloads and save them to a directory for further processing.

## USAGE
```
❯ 2bfuzz -h
usage: 2bfuzz [-h] [--ip IP] [--port PORT] [--generator [path/to/save/]] [--bytes] [--radamsa FILE] [--count COUNT] [--sleep COUNT]

Options:
  -h Show this help message and exit
  -i Server IP address.
  -p Server port number.
  -g Path where to save generated payloads.
  -b 2-byte generator.
  -r Radamsa generator with a given pattern stored in a file.
  -c Number of payloads to generate with Radamsa.
  -s Number of seconds to wait between each connection while fuzzing.
```
### 1. FUZZER
* Fuzzing TCP server (`127.0.0.1:8000`) using `2-byte generator` and `Radamsa generator` with a `test_file` as a pattern.
```zsh
❯ 2bfuzz -i 127.0.0.1 -p 8000 -b -r test_file

[+] The service on: 127.0.0.1:8000 is up.
[+] Starting fuzzing the first byte.
[+] Starting fuzzing the first 2 bytes.
[+] The service is down. The last payload could crash it.
   Content of the last payload: b'\xbd\x0e'
```
* Example content of `test_file`
```
GET / HTTP/1.1
Host:localhost:8000

```
### 2. GENERATOR
* Generate all possible 2-byte payloads and 1000 Radamsa payloads. Save them to the specified directory (`/tmp/2b_payloads`).
```zsh
❯ 2bfuzz -g /tmp/2b_payloads/ -b -r test_file -c 1000
❯ ls  /tmp/2b_payloads | head
0.2B
1.2B
1.rad
10.2B
10.rad
100.2B
100.rad
1000.2B
1000.rad
10000.2B
[...]

❯ cat /tmp/2b_payloads/1000.rad
GET / HTTP/340282366920938463463374607431768211456.1
GET / HTTP/1.1
Host:localhost:8000
```
## INSTALLATION
```
git clone https://github.com/Karmaz95/2bfuzz.git
cd 2bfuzz
pip install -r requirements.txt
chmod +x 2bfuzz.py
sudo mv 2bfuzz.py /usr/local/bin/2bfuzz
```
To make the Radamsa work, you must install it on your system.
* MacOS
```
brew install radamsa
```
* Linux
```
sudo apt install -y radamsa
```
## GENERATORS DESCRIPTION
The script includes two generators: 
* `two_bytes_generator` - generates all possible 2-byte payloads and saves them to the specified directory
* `radamsa_generator` - generates payloads using the Radamsa engine and allows you to specify the number of payloads to generate and the directory to save them in.

## FUZZER DESCRIPTION
The TCP fuzzer includes two fuzzing engines which first establish a connection with the server (`TCP SYN` <-> `TCP SYN-ACK` <-> `ACK` packets to complete the three-way handshake) and then: 
* `two_bytes_fuzzer` - fuzzes the first two bytes using all possible combinations.
* `radamsa_fuzzer` - fuzzes the service using payloads generated by the Radamsa engine with a `test_sample` as a pattern.

The script also includes functions to check if the target service is responding before fuzzing and handling the TCP connection.

## WHEN TO USE IT 
When you cannot see the source code or recompile the binary to use it, for example, with `AFL`, or just want to approach it in a "black box" way. The main objective of the tool is to `crash the target`.

## WHY ANOTHER FUZZER
I am writing this fuzzer because I want to:
* wrap Radamsa so I can check the state of the server after each payload
* have a template for fuzzing things in a black box way for further research,
* optimize the fuzzing techniques and tools that already exist,
* learn about fuzzing.
## FUTURE WORK AKA TODO
1. Check the PID of the process if fuzzing locally for crash detection.
2. Write new generators.
