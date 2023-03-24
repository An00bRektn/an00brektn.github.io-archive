---
layout: post
title: "Cyber Apocalypse 2023: Elliptic Labryinth"
image: '/img/htb-cyber-apocalypse-23/ca-logo-2023'
date:   2023-03-24 00:00:00
tags:
- crypto
- ecc
- coppersmith
- htb-cyber-apocalypse
description: 'Not to be confused with ellipses.'
categories:
published: true
comments: false
---

![logo](https://an00brektn.github.io/img/cyber-apocalypse-23/ca-logo-2023.webp)

## Intro
I'll be honest, I kind of dropped the ball on the crypto category this time around, but not on Elliptic Labryinth, a medium rated challenge that had to be rereleased due to unintended solves, so we'll be covering both intended and unintended versions.

In version 1 of the challenge, we're given a server that is using the parameters of an elliptic curve to encrypt the flag. However, unlike traditional elliptic curve systems, we don't actually know what the parameters are. We're given the prime modulus and the upper 200-300 bits of the coefficients. But, the server also lets us generate an arbitrary number of points on the curve, which we can then use to calculate the parameters on our own using some algebra.

Version 2 of the challenge removed the point generation function, and only gives us one point. This would normally be a problem, but because we have a relation between all of our variables (the elliptic curve polynomial), we can apply Coppersmith's method to find small roots of our polynomial and find the values chopped off of the coefficients. 

* buh
{:toc}

### Description
`As you navigate through the labyrinth inside the tomb, you encounter GPS inaccuracies that make it difficult to determine the correct path to the exit. Can you overcome the technical issues and use your instincts to find your way out of the maze?`

## The Challenge (v1)
We're given source code to the server.
```python
import os, json
from hashlib import sha256
from random import randint
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from sage.all_cmdline import *
from secret import FLAG

class ECC:
    def __init__(self, bits):
        self.p = getPrime(bits)
        self.a = randint(1, self.p)
        self.b = randint(1, self.p)

    def gen_random_point(self):
        return EllipticCurve(GF(self.p), [self.a, self.b]).random_point()

def menu():
    print("1. Get parameters of path")
    print("2. Get point in path")
    print("3. Try to exit the labyrinth")
    option = input("> ")
    return option

def main():
    ec = ECC(512)

    while True:
        choice = menu()
        if choice == '1':
            r = randint(ec.p.bit_length() // 3, 2 * ec.p.bit_length() // 3)
            print(
                json.dumps({
                    'p': hex(ec.p),
                    'a': hex(ec.a >> r),
                    'b': hex(ec.b >> r)
                }))
        elif choice == '2':
            A = ec.gen_random_point()
            print(json.dumps({'x': hex(A[0]), 'y': hex(A[1])}))
        elif choice == '3':
            iv = os.urandom(16)
            key = sha256(long_to_bytes(pow(ec.a, ec.b, ec.p))).digest()[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            flag = pad(FLAG, 16)
            print(
                json.dumps({
                    'iv': iv.hex(),
                    'enc': cipher.encrypt(flag).hex()
                }))
        else:
            print('Bye.')
            exit()

if __name__ == '__main__':
    main()

```

### Solution
The `EllipticCurve` class is initializing an elliptic curve in Weierstrass form, that is:
\\[\begin{align\*} y^2 &= x^3 + ax + b \end{align\*}\\]

over the field $$\mathbb{Z}_p$$. Since we can generate any number of points, the only unknowns are $$a$$ and $$b$$, which allows us to set up a system of equations.

\\[\begin{align\*} y_1^{2} &= x_1^3 + ax_1 + b_1 \\\\ y_2^2 &= x_1^3 + ax_2 + b_2 \end{align\*}\\]

If you've taken any kind of algebra class, the rearranging should be trivial, but eventually, we get here:

\\[\begin{align\*} a &= (x_1 - x_2)^{-1}(y_1^2 - y_2^2)-(x^3_1 - x^3_2) \\\\ b &= y_2^2 - x^3_1 - ax_1 \end{align\*}\\]

So, we can implement this in code.

```python
from pwn import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import json

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        print("[!] Error: Insufficient args")

context.log_level = 'debug'
io = start()

def get_truncated_params():
    io.sendlineafter(">", "1")
    output = json.loads(io.recvlineS().strip())
    return int(output["p"], 16), int(output["a"], 16), int(output["b"], 16) 

def get_random_point():
    io.sendlineafter(">", "2")
    output = json.loads(io.recvlineS().strip())
    return int(output["x"], 16), int(output["y"], 16)

def get_encrypted_flag():
    io.sendlineafter(">", "3")
    output = json.loads(io.recvlineS().strip())
    return bytes.fromhex(output["iv"]), bytes.fromhex(output["enc"])

x_1, y_1 = get_random_point()
x_2, y_2 = get_random_point()
p, a_trun, b_trun = get_truncated_params()

# Why use coppersmith when you gave me two points LMAO
a = pow(x_1 - x_2, -1, p) * (pow(y_1, 2, p) - pow(y_2, 2, p) - (pow(x_1, 3, p) - pow(x_2, 3, p))) % p
b = (pow(y_1, 2, p) - pow(x_1, 3, p) - a * x_1) % p

iv, ct = get_encrypted_flag()
key = sha256(long_to_bytes(pow(a, b, p))).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)
success(flag)
```

**Flag**: `HTB{d3fund_s4v3s_th3_d4y!}`
(this flag will make sense after covering the intended solution)

Short solution, but that's usually the case with these unintended solution. But now, for the main event.

## The Challenge (v2)
The big difference between version 1 and version 2 is the absence of the point generator.
```python
A = ec.gen_random_point()
print("This is the point you calculated before:")
print(json.dumps({'x': hex(A[0]), 'y': hex(A[1])}))
while True:
	choice = menu()
	if choice == '1':
		r = randint(ec.p.bit_length() // 3, 2 * ec.p.bit_length() // 3)
		print(
			json.dumps({
				'p': hex(ec.p),
				'a': hex(ec.a >> r),
				'b': hex(ec.b >> r)
			}))
	elif choice == '2':
		iv = os.urandom(16)
		key = sha256(long_to_bytes(pow(ec.a, ec.b, ec.p))).digest()[:16]
		cipher = AES.new(key, AES.MODE_CBC, iv)
		flag = pad(FLAG, 16)
		print(
			json.dumps({
				'iv': iv.hex(),
				'enc': cipher.encrypt(flag).hex()
			}))
	else:
		print('Bye.')
		exit()
```

### Solution
With the removal of the point generator, we're limited to one equation, so now we actually have to pay attention to these parameters. When we're given $$a$$ and $$b$$, they get bit shifted right by some amount $$170 \leq r < 380$$. This is hard to write in math, so we can rewrite this as

\\[\begin{align\*} a &= a_t + a_r \\\\ b &= b_t + b_r \end{align\*}\\]

where $$a_t, b_t$$ represent the truncated numbers we get, and $$a_r, b_r$$ is the value that comes off of the truncation. Knowing this, we can revisit our elliptic curve equation and substitute:

\\[\begin{align\*} y^2 = x^3+ax+b &\rightarrow y^2 = x^3 + (a_t+a_r)x + (b_t+b_r) \\\\ &\rightarrow 0 = x^3 + (a_t+a_r)x + (b_t+b_r) - y^2 \end{align\*}\\]

We know how all of the variables are related, and the only values we don't know are $$a_r$$ and $$b_r$$, so the question is, how do we solve for them?

#### Coppersmith's Method
An in-depth discussion of Coppersmith's method is a bit outside the scope of this writeup, but the motivating question it addresses is "How do we find zeroes of polynomials modulo an integer"? From your basic algebra class, factoring polynomials of lower degrees is very easy. However, in this case, we need to deal with the prime modulus, which is effectively a randomizing function. As far as I'm aware, we don't have anything to deal with these kinds of polynomials directly.

But, what if we could solve a different problem that's easier to solve? Coppersmith's method seeks to take a polynomial with big coefficients, and bring it down to a polynomial with smaller coefficients, but still the same zeroes. It works like this:

1. Construct a [lattice](https://en.wikipedia.org/wiki/Lattice_(group)) in a particular way using the polynomial.
2. Apply the [Lenstra–Lenstra–Lovász](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm) (LLL) algorithm to reduce the basis.
3. Take the reduced basis and build our polynomial with smaller coefficients.

For those who don't know, a lattice is essentially a big grid of vectors where any addition and subtraction of vectors in the lattice give another vector in the lattice. 

![lattice](https://upload.wikimedia.org/wikipedia/commons/thumb/2/27/Lattice-reduction.svg/1200px-Lattice-reduction.svg.png)

The image above shows a lattice formed from a **basis** of $$u_1$$ and $$u_2$$. Notice that lattices are not unique; the basis of $$v_1$$ and $$v_2$$ forms the same lattice. When we apply the LLL algorithm, we attempt to find the basis defined by the smallest vectors in the lattice. If can construct our initial basis in a specific way, then reducing the basis will lead to finding that easier-to-solve polynomial.

At the end of the day, even if this doesn't make total sense, we're reducing a very complex problem to one we know we produce at least a close approximate solution for, to solve an easier problem. 

#### Sage Script
The full process and algorithm is a little complex, but luckily there are a number of implementations out there. The solution to the first version suggested using [defund's](https://github.com/defund/coppersmith) implementation, but many other players have reported greater success with [Joseph Surin's](https://github.com/josephsurin/lattice-based-cryptanalysis) version. Either one works, and we can write the below SageMath code to solve.

```python
from pwn import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import json

# https://github.com/defund/coppersmith
load('coppersmith.sage') 

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        print("[!] Error: Insufficient args")

context.log_level = 'debug'
io = start()

def get_truncated_params():
    io.sendlineafter(">", "1")
    output = json.loads(io.recvlineS().strip())
    return int(output["p"], 16), int(output["a"], 16), int(output["b"], 16) 


def get_encrypted_flag():
    io.sendlineafter(">", "2")
    output = json.loads(io.recvlineS().strip())
    return bytes.fromhex(output["iv"]), bytes.fromhex(output["enc"])

io.recvlineS()
init_point = json.loads(io.recvlineS().strip())
x, y = int(init_point["x"], 16), int(init_point["y"], 16)

solved = False

# defund's implementation can sometimes choke, especially if the value of r
# is on the higher end, so we just loop it, because we can.
while not solved:
    p, a_t, b_t = get_truncated_params()

    # We're modeling the truncated integer as subtraction, which is correct
    # but we also need to remember that the actual integer that's being deducted
    # is coming off of a 512 bit number
    aa_t = int(a_t) << (512-int(a_t).bit_length())
    bb_t = int(b_t) << (512-int(b_t).bit_length())

    load('./coppersmith.sage')
	# defining a multivariate polynomial ring
    R.<da,db> = PolynomialRing(Zmod(p))
    f = x**3 + (da+aa_t)*x + (db+bb_t) - y**2 # defining the polynomial
    a_0, b_0 = small_roots(f, [2**512,2**512], d=2)[0] # via defund

    a = a_0 + aa_t
    b = b_0 + bb_t 

    iv, ct = get_encrypted_flag()
    key = sha256(long_to_bytes(pow(int(a), int(b), int(p)))).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = cipher.decrypt(ct)
    info(flag)
    if flag[0:3] == b'HTB':
        success(flag)
        solved = True
        break
```

**Flag**: `HTB{y0u_5h0u1d_h4v3_u53d_c00p325m17h}`