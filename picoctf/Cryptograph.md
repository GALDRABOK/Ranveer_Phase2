
# 2. Custom encryption

> Put in the challenge's description here

## Solution:
1.Analyzing the puthon code
```
from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def encrypt(plaintext, key):
    cipher = []
    for char in plaintext:
        cipher.append(((ord(char) * key*311)))
    return cipher


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key):
    cipher_text = ""
    key_length = len(text_key)
    for i, char in enumerate(plaintext[::-1]):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return cipher_text


def test(plain_text, text_key):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print("Enter prime numbers")
        return
    a = randint(p-10, p)
    b = randint(g-10, g)
    print(f"a = {a}")
    print(f"b = {b}")
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    semi_cipher = dynamic_xor_encrypt(plain_text, text_key)
    cipher = encrypt(semi_cipher, shared_key)
    print(f'cipher is: {cipher}')


if __name__ == "__main__":
    message = sys.argv[1]
    test(message, "trudeau")

```
The original code executes the steps in this sequence:

Diffie-Hellman Key Exchange (Generates the shared_key).(found the name after research)<br>

Dynamic XOR (Encrypts the reversed message).<br>

Multiplication (Scales the result by the key).<br>

To decrypt, we must reverse these steps

2.We first look at the process used to generate the Shared Secret Key, which is vital for decryption.
We find values from the python program and file enc_flag
```
p = 97
g = 31
a = 97
b = 22

v = pow(g, b, p) 
shared_key = pow(v, a, p)
```
After calculation
```
shared_key =94
```
3.Now we write the decryption function by reversing the last two encryption steps in order.
```
# The list of numbers (the encrypted message) obtained from the challenge files.
cipher_stream = [237915, 1850450, 1850450, 158610, 2458455, 2273410, 1744710, 1744710, 1797580, 1110270, 0, 2194105, 555135, 132175, 1797580, 0, 581570, 2273410, 26435, 1638970, 634440, 713745, 158610, 158610, 449395, 158610, 687310, 1348185, 845920, 1295315, 687310, 185045, 317220, 449395]

# The shared secret key derived from the Diffie-Hellman calculation (94).
dh_secret_key = 94

# The text key used for the dynamic XOR operation.
xor_key_string = "trudeau"

def decrypt(cipher_stream, dh_secret_key, xor_key_string):
    # STEP 1: Reverse Multiplication (Obtain pre-multiplied ASCII values)
    
    # The original multiplier was shared_key * 311.
    scale_factor = dh_secret_key * 311
    
    # Divide the cipher numbers by the scale_factor to get the ASCII value.
    # We call this the 'de-scaled' stream.
    de_scaled_stream = [chr(num // scale_factor) if num != 0 else '\x00' for num in cipher_stream]
    
    # STEP 2: Reverse XOR (Decrypt the character stream)
    
    key_size = len(xor_key_string)
    decrypted_char_list = []
    
    # Iterate through the de-scaled stream to reverse the XOR operation.
    for index, char_code in enumerate(de_scaled_stream):
        key_char = xor_key_string[index % key_size]
        # XORing with the key again reverses the operation.
        final_ascii_char = chr(ord(char_code) ^ ord(key_char))
        decrypted_char_list.append(final_ascii_char)
        
    # STEP 3: Restore String Order
    # The encryption reversed the message, so we reverse it back to get the flag.
    # Join the characters and reverse the result.
    return "".join(decrypted_char_list)[::-1]

# Execute and print the flag
flag = decrypt(cipher_stream, dh_secret_key, xor_key_string)
print(flag)
```


## Flag:

```
picoCTF{custom_d2cr0pt6d_66778b34}
```

## Concepts learnt:

- Include the new topics you've come across and explain them in brief
- 

## Notes:

- Include any alternate tangents you went on while solving the challenge, including mistakes & other solutions you found.
- 

## Resources:

- Include the resources you've referred to with links. [example hyperlink](https://google.com)


***

