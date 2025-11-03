# 1. RSA oracle

Can you abuse the oracle?
An attacker was able to intercept communications between a bank and a fintech company. They managed to get the message (ciphertext) and the password that was used to encrypt the message.
After some intensive reconassainance they found out that the bank has an oracle that was used to encrypt the password and can be found here nc titan.picoctf.net 52896. Decrypt the password and use it to decrypt the message. The oracle can decrypt anything except the password.

## Solution:
1.RSA property:
```
E(m1) * E(m2) mod N = E(m1*m2 mod N)
```
<br>

2.I choose to encrypt ASCII '2' which is hex 0x32 (50 in decimal).<br>
The cipher returned is:
```
4707619883686427763240856106433203231481313994680729548861877810439954027216515481620077982254465432294427487895036699854948548980054737181231034760249505
```
Let this number be c2
```
c2=E(50)
```
<br>

3.multiply enc(password) * enc(50)<br>
I multiplied the given password.enc integer with this returned ciphertext integer(let product be c3).I sent that product to the oracle D (decrypt).<nr>
The oracle returned:
```
10997708943982761084006315359417483254965299487204584192712335192036789472336196626179282134890223733758401125471056267054908321079024432384222437910457194483711112753102678178170094968585207806212096960492328042941752878907452001886104974213833155189826877814877017136978779880432127774578986380439317174695
decrypted ciphertext as hex (c ^ d mod n): a9573f66360  #let this be m3
decrypted ciphertext: 
söc`
```
converting m3 to decimal
```
a9573f66360(hex) = 11637011932000(dec)
```

4.Now,
```
c3=E(m1*m2)
```
If we decrypt both sides we get
```
D(c3)=D(E(m1*m2))
```
and decryption of c3 gets us m3
```
m3=m1*m2
```
we know m2 and m3,from the relation above we can get m1
```
m1=m3/m2
m1=11637011932000/50
m1=232740238640
```

5.Converting m1 to hex then to ASCII we get
```
60f50
```
This is out password.

6.Final decrypt,we use the openssl locally using the command
```
openssl enc -aes-256-cbc -d -in secret.enc -pass pass:60f50
```
and we get the output
```
 *** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
picoCTF{su((3ss_(r@ck1ng_r3@_60f50766}%  
```
## Flag:

picoCTF{su((3ss_(r@ck1ng_r3@_60f50766}

## Concepts learnt:

- RSA multiplicativity— Textbook RSA (no padding) is multiplicative:This allows an attacker with an encryption/decryption oracle to manipulate ciphertexts and recover plaintext relationships.
- OpenSSL salted format:files starting with “Salted__” use a KDF to turn password into AES key and iv. if you guess the password wrong or guess the wrong encoding (raw bytes vs ascii) you get “bad decrypt”.
- 	modular inverse for division:once N is known and we have m_prime = m * password mod N then password = m_prime * inv(m,N) mod N.

## Resources:

- Understanding Cryptography — Christof Paar & Jan Pelzl.(https://cacr.uwaterloo.ca/hac/)
- GeeksForGeeks RSA and Modular Arithmetic articles (https://www.geeksforgeeks.org/rsa-algorithm-cryptography/)(https://www.geeksforgeeks.org/modular-multiplicative-inverse/)
- Decimal to Hex(https://www.rapidtables.com/convert/number/decimal-to-hex.html?x=232740238640)
- Hex to ASCII(https://www.rapidtables.com/convert/number/hex-to-ascii.html)

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
For exact root:Convert integer root to hex then to bytes .<br>
```
from sympy import integer_nthroot
N = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287

c = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808146919581675891411119628108546342758721287307471723093546788074479139848242227243523617899178070097350912870635303707113283010669418774091018728233471491573736725568575532635111164176010070788796616348740261987121152288917179932230769893513971774137615028741237163693178359120276497700812698199245070488892892209716639870702721110338285426338729911942926177029934906215716407021792856449586278849142522957603215285531263079546937443583905937777298337318454706096366106704204777777913076793265584075700215822263709126228246232640662350759018119501368721990988895700497330256765579153834824063344973587990533626156498797388821484630786016515988383280196865544019939739447062641481267899176504155482

e = 3

for i in range(1,50000):
    val = i*N + c
    root, perfect = integer_nthroot(val, 3)
    if perfect:
        print(root)
        print("root=",root)
        print("k=",i)
        b = bytes.fromhex(hex(root)[2:])
        print(b)


```
Output:
```
1787330808968142828287809319332701517353332911736848279839502759158602467824780424488141955644417387373185756944952906538004355347478978500948630620749868180414755933760446136287315896825929319145984883756667607031853695069891380871892213007874933611243319812691520078269033745367443951846845107464675742664639073699907476681022428557437
b'                                                                                                        picoCTF{e_sh0u1d_b3_lArg3r_60ef2420}'
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

