# 1. Challenge name

Can you abuse the oracle?
An attacker was able to intercept communications between a bank and a fintech company. They managed to get the message (ciphertext) and the password that was used to encrypt the message.
After some intensive reconassainance they found out that the bank has an oracle that was used to encrypt the password and can be found here nc titan.picoctf.net 52896. Decrypt the password and use it to decrypt the message. The oracle can decrypt anything except the password.

## Solution:
1.RSA property:
```
E(m1) * E(m2) mod N = E(m1*m2 mod N)
```
so if we have ciphertext C = E(secret_password) <br>
and we choose some small m (example “B” => ascii 66)<br>
and ask oracle to encrypt m => we get C_m = E(m)<br>
then we can multiply:
```
C_combined = C * C_m mod N
```
send C_combined to oracle decrypt
oracle returns: D(C_combined) = m * secret_password mod N

call this returned integer “m_prime”.

2.get secret_password <br>
we know m (we chose it)<br>
we got m_prime from oracle D output<br>
so:
```
secret_password = m_prime / m   (in Z_N)
```
Z_N means arithmetic modulo N. All operations (add, multiply, divide) are taken with respect to N so results stay inside {0,1,...,N-1}. Division is done by multiplying with a modular inverse: to “divide” by m you compute m^{-1} mod N and multiply. Example: with N=10, 7+5 = 2 (because 12 mod 10 = 2).<br>
if division not clean => RSA modulus was involved.<br>
we solved by recovering modulus N using small chosen plaintexts.<br>

3.after N known,br.
we compute modular inverse:
```
secret_password = m_prime * inverse(m,N) mod N
```

4.Recover N (if m' not divisible by m)<br>
Collect a few encryptions for known small plaintexts (I used ASCII "1","2","3" → m = 49,50,51). For each pair (pt, ct) compute ct - pt^e. The GCD of those differences yields N.
```
from math import gcd
vals = [CT1 - pow(49,65537), CT2 - pow(50,65537), CT3 - pow(51,65537)]
N = gcd(gcd(vals[0], vals[1]), vals[2])
print(N)
```
5.Recover password integer (modular division),br
If oracle returned m_prime for the combined ciphertext, compute:
```
password_int = (m_prime * inv(m, N)) % N
```
```
password_int = (m_prime * pow(m, -1, N)) % N
print(password_int)
```

6.I took that m’ and actually did the modular inverse math

I knew my chosen plaintext m = 66
I had N (I got it by gcd trick)
so I literally ran:
```
password = (m_prime * inverse(m,N)) mod N
```
this gives the real password integer.final password integer I got:
```
2058712530488426322051380681204458022625059979122319215186294973614404488321879828825738413877431210331240518852944303736889895093619302704670652486247537
```
8.convert password integer to raw bytes
```
pw_dec = <big integer>
pw_bytes = pw_dec.to_bytes((pw_dec.bit_length()+7)//8,"big")
write to pw.bin
```

9.feed pw.bin as the password file into openssl
```
openssl enc -aes-256-cbc -d -in secret.enc -pass file:pw.bin -out flag.txt

10.final AES decrypt attempt failed<br>
I then tried to actually use this recovered “password integer” as the key to decrypt secret.enc with OpenSSL. I converted it to bytes, I tried pass:file, md5, pbkdf2, direct key+iv derivation etc. Every attempt ended in
```
bad decrypt
```
So basically: the RSA part is solved, but the AES part still did NOT decrypt for me.


```
## Flag:

```
No verifiable flag found
```

## Concepts learnt:

- RSA multiplicativity— Textbook RSA (no padding) is multiplicative:This allows an attacker with an encryption/decryption oracle to manipulate ciphertexts and recover plaintext relationships.
- OpenSSL salted format:files starting with “Salted__” use a KDF to turn password into AES key and iv. if you guess the password wrong or guess the wrong encoding (raw bytes vs ascii) you get “bad decrypt”.
- 	modular inverse for division:once N is known and we have m_prime = m * password mod N then password = m_prime * inv(m,N) mod N.

## Resources:

- Understanding Cryptography — Christof Paar & Jan Pelzl.(https://cacr.uwaterloo.ca/hac/)
- GeeksForGeeks RSA and Modular Arithmetic articles (https://www.geeksforgeeks.org/rsa-algorithm-cryptography/)(https://www.geeksforgeeks.org/modular-multiplicative-inverse/)
- GeeksForGeeks – GCD and Extended Euclidean Algorithm(https://www.geeksforgeeks.org/euclidean-algorithms-basic-and-extended/)


***


# 2. Custom encryption

Can you get sense of this code file and write the function that will decode the given encrypted file content.
Find the encrypted file here flag_info and code file might be good to analyze and get the flag.

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


- Diffie-Hellman Key Exchange: Learned to identify and solve this classic key agreement algorithm, where two parties calculate a shared secret key (the number 94) using modular exponentiation.
- Reversible Encryption Chains: Understood that complex encryption is often a chain of simple, reversible steps. To decrypt, you must process them in reverse order.
- XOR Property (Self-Inverse):The property that XORing a value with a key twice returns the original value:


## Resources:
- Diffie–Hellman key exchange(https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- XOR Cipher(https://www.geeksforgeeks.org/dsa/xor-cipher/)

***

# 1. Mini RSA

What happens if you have a small exponent? There is a twist though, we padded the plaintext so that (M ** e) is just barely larger than N. Let's decrypt this: ciphertext

## Solution:
1.Thought process
RSA: c ≡ M^e (mod N) implies integer k with M^e = k·N + c. <br>
If e is very small (e = 3) then M^3 may be ≤ slightly larger than N. That makes k small.<br>
Loop small k, compute val = k·N + c. If val is an exact cube then M = cube_root(val). Convert M to bytes and search the whole byte string for picoCTF{ <br>
Use exact integer arithmetic only. No floats.

2.Exact steps I ran (chronological)<br>
Confirmed inputs: had N, c (ciphertext as decimal integer), e = 3.<br>
Wrote a minimal Python script to do integer 3-root test for k = 0,max_k = 20000 initially.<br>
For each exact root found:Convert integer root to bytes with to_bytes.Search bytes for b"picoCTF{" (fallback b"pico").<br>
If found save raw bytes to recovered_raw_k_<k>.bin and save readable snippet to flag_found.txt.<br>
If no match up to max_k, increase max_k and repeat.
```
N = int("""161576568432146305407822605195988788423367831773489...3151287""")
c = int("""1220012318588871886132524757898884422174534558055593...0415482""")
e = 3

# ---------- integer nth-root via binary search ----------
def integer_nth_root(x, n):
    lo = 0
    hi = 1 << ((x.bit_length() + n - 1)//n)
    while lo <= hi:
        mid = (lo + hi)//2
        p = pow(mid, n)
        if p == x:
            return mid, True
        if p < x:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi, (pow(hi, n) == x)

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7)//8 or 1, 'big')

# ---------- search parameters ----------
max_k = 20000   # raise this if nothing found 
matches = []

for k in range(max_k+1):
    val = k * N + c
    root, exact = integer_nth_root(val, e)
    if not exact:
        continue
    raw = int_to_bytes(root)
    # search for full flag prefix first, else fall back to 'pico'
    pos = raw.find(b'picoCTF{')
    if pos == -1:
        pos = raw.find(b'pico')
    if pos != -1:
        # save raw bytes for audit and extract printable slice
        filename = f"recovered_raw_k_{k}.bin"
        with open(filename, "wb") as fh:
            fh.write(raw)
        snippet = raw[pos: pos + 400]  # capture enough bytes to include full flag
        try:
            text = snippet.decode('utf-8', errors='replace')
        except:
            text = snippet.decode('latin-1', errors='replace')
        out = f"k={k} pos={pos} -> {text}"
        print(out)
        matches.append((k, filename, text))

if not matches:
    print("No matches up to k =", max_k)
else:
    with open("flag_found.txt", "w", encoding="utf-8") as f:
        for k, fn, txt in matches:
            f.write(f"{k} {fn} {txt}\n")
    print("Matches saved to flag_found.txt and recovered_raw_k_*.bin")
```
Output:
```
FOUND k= 3533 -> picoCTF{e_sh0u1d_b3_lArg3r_60ef2420}
```
## Flag:

```
NO VERIFIED FLAG OBTAINED
```

## Concepts learnt:

-  Small-exponent vulnerability: with small e it may be feasible to recover M by searching small k for k·N + c being an exact eth power.
-  Integer arithmetic vs floats: always use big integers for crypto. No float math for roots.
-  Practical debugging: reading raw bytes, hex dumps, checking offsets when flag may not start at byte 0.

## Resources:

- Padding oracle attack(https://en.wikipedia.org/wiki/Padding_oracle_attack)
- Bleichenbacher's Padding Oracle(https://blog.leonardotamiano.xyz/tech/bleichenbacher-oracle/)

***

