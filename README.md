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

It seems that the binary is using a Magic Value which is defined before the compilation.\n
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




