# HavocC2Defense

I will explain how I analyzed malicious havoc binaries.
For now I have been able to create a Yara rule based on Dynamic API Resolution.

## Network

I created an isolated network with 3 machines : 

- an attacker
- the havoc server
- a victim

![Network-Havoc](https://github.com/user-attachments/assets/f62f026c-e73d-4731-aa01-f9c1921fd98f)

## Analyzing the source code

By analyzing the C code of the demon (havoc malware), I found a header.

![Payload-Demon-src-Demon c____Demon_header](https://github.com/user-attachments/assets/a5704787-393d-44a0-9c6f-7cf2bce37fb1)

It seems that the binary is using a Magic Value which is defined before the compilation.
We can find an AES key assuming that the data sent to the C2 are encrypted using this key.

We can also see in the source code of the demon that the malware is resolving API dynamically.

![resolving_api_dynamically](https://github.com/user-attachments/assets/646a508f-235f-4f70-8f94-fe423c8393b5)

And we can find their hexa values in the Defines.h code and the Magic value is also defined here.

![Payload-Demon-include-common-Defines h____Demon_Magic_Value](https://github.com/user-attachments/assets/09359e62-42b0-40db-9101-c85fc0d36280)

![Payload-Demon-include-common-Defines h____Win32_functions](https://github.com/user-attachments/assets/dcf76a84-1c20-4e5c-9fba-745e1948404c)

## Creating a Yara rule based on Dynamic API Resolution

Due to the Dynamic API Resolution, we should be able to recover these different functions by decompiling the binary using Ghidra.
Moreover, Ghidra tells that the binary doesn't import any function which can indicate Dynamic API Resolution.

![Find_Win32_function_in_ghidra](https://github.com/user-attachments/assets/1fd9440c-e53a-4786-85e4-254904471af8)

And bingo ! But we need to transform this in little endian as Ghidra shows on the left.

![Find_Win32_function_in_ghidra_inversed](https://github.com/user-attachments/assets/3e5dd9d9-f1f5-4626-a797-2e9d8af81e3c)

We can copy all the functions found in the Defined.h into a text file, and run this python script.

```
import re

with open("win32_function.txt", "r") as file:
    text = file.read()

pattern = r'#define\s+(\w+)\s+(0x[0-9a-fA-F]+)'
matches = re.findall(pattern, text)

def inverse_hex(value):
    value = value[2:]

    value = value.zfill(8)
    byte1 = value[6:8]
    byte2 = value[4:6]
    byte3 = value[2:4]
    byte4 = value[0:2]

    return f"{byte1} {byte2} {byte3} {byte4}"

i = 1
for match in matches:
    name = match[0]
    hex_value = match[1]
    inverted_hex = inverse_hex(hex_value)
    s = "$function" + str(i)
    i+=1
    print(s + " = {" + inverted_hex + "} //" + name)
```

And we can import the output into our Yara rule !

![inverse_hex_+_correct_strings_format](https://github.com/user-attachments/assets/59d47e6e-af4e-4750-9553-05941c834796)

We can try the yara.

![yara_winapi_triggered](https://github.com/user-attachments/assets/7705bf51-5c09-4929-9998-e6d6acbdcc51)

## Analyzing Havoc traffic in a PCAP.

I started by playing some HTTP traffic between the victim and the Havoc C2, and I listened the network using Wireshark. I captured the Demon Initialization, some executed commands, uploaded and downloaded files.

By analyzing the PCAP, we see different COMMAND IDs : 

- 63 : Demon Initialization
- 1 : GetJobs (executed commands, uploaded and downloaded files...)

These IDs are always sent by the victim to the Havoc C2.

The Demon always sends the header over the network. But during the Demon Initialization, it also sends the AES key and the AES IV. 

![find_keys](https://github.com/user-attachments/assets/bed2c517-73b4-4b5a-859c-abe3492dfb86)

If you wanna check if the keys are valids, you can read the teamserver database which is located on the Havoc server.

![sqlite_recover_AES_from_teamserver](https://github.com/user-attachments/assets/adfb95ba-8622-4d10-85f6-670d279040db)

So, we can obtain the AES parameters and use them to decrypt other packets. We need to remove the header before trying the decryption.

![traffic_in_pcap](https://github.com/user-attachments/assets/cc9d3146-d0c2-40a8-8c3c-ec985b4a3656)
![get_info_cyberchef_decrypted](https://github.com/user-attachments/assets/b6c5d5f7-6998-4d4f-886d-db84f099ea6c)

Ok, we're able to find AES keys, and decrypt packets. I developed a Python script which will search for AES keys, the script can also decrypt packets if we provide the AES key, AES IV and the ip address of the C2. Due to encoding problems, it was mandatory to save the outputs into files.

I got some errors while installing Pyshark, so I used a Python environment, which is available on the repo.
I also created a docker image.

![http_parser_docker_usage](https://github.com/user-attachments/assets/fdd43349-f011-40e0-8ca5-79d7327dacf0)
![decrypted_traffic](https://github.com/user-attachments/assets/f66b90de-84ad-4bf3-8ae6-b169414f30b6)

We canno't always find the Demon Initialization in the PCAP, sometimes it has not been recorded. So, I searched for another way to find AES parameters. My first idea was to investigate the memory.

## Analyzing the memory

For the rest of the blog, I used another Demon with different AES key and IV.

I dumped the victim machine's memory using DumpIt while the Demon was running.

I started by dumping the process from the memory dump using volatility2.

![dump_bin_mem](https://github.com/user-attachments/assets/a1a36476-0916-495e-b5e4-30b9e7da1027)

We can analyze the dump using hexeditor and look for the magic value **DEADBEEF**.

![hexdump](https://github.com/user-attachments/assets/a185ace1-d281-4955-97a2-2fce40149303)

And we can find the entire header !

Based on this header, we can create a Regex and use it in a volatility plugin.

![regex](https://github.com/user-attachments/assets/6cc6091b-ad8c-4621-a3bd-cac58330fdb8)
![vol_usage](https://github.com/user-attachments/assets/44de439a-4031-49a0-a647-a840762d00ae)

We are able now to find Havoc headers in memory using Volatility2. I did the same for Volatility3 :) .

We can use the key and the IV to decrypt some HTTP traffic (or HTTPS if you have the private key which is located on the Havoc server).
