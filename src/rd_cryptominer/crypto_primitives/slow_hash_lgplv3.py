"""
This is a Python implementation of the cryptonight slow hash. It includes a
short run_tests() with an example call. It is based on (and was checked against)
the original Monero Project code (https://github.com/monero-project/monero)
with and without the 2018 April hard fork variant.

First version was written for Python 2.7 by Patrik Lundin,
port to Python 3.6 + several tweaks were brought by Thomas Eder

The cryptonight algorithm remains extremely slow,
around 0.03 hashes per second on a regular i5 CPU.
As such, it's meant more as a consise summary
of the algorithm than usefully runnable code. It's not particularly
optimized, and where possible prior optimization has been removed.

There are no outside dependencies (except "time" which is only used
in the example) with everything reimplemented in pure python, including
AES, Keccak, Blake, Groestl, JH, and Skein.
"""

__author__ = "Patrik Lundin / Thomas Eder"
__copyright__ = "Copyright 2018, nothisispatrik.com" 
__license__ = "LGPL v3. Algorithms/constants may be (C) 2014-2018 The Monero project or (C) 2012-2014\
The Cryptonote Developers. All code is original"
__email__ = "patrik@nothisispatrik.com / thomas@gaudia-tech.com"
__status__ = "Prototype"

from functools import reduce


from .hash_constants import *



    # Single AES round, no round key (can be xor:ed in after)

    # Here implemented using TBoxes, which is relativily fast, but
    # vulnerable to cache-timing attacks. Not safe for other purposes.
def round(b): 
    def col(c1, c2, c3, c4):
        t = S1[c1] ^ S2[c2] ^ S3[c3] ^ S4[c4]
        t1 = t >> 0 & 255
        t2 = t >> 8 & 255
        t3 = t >> 16 & 255
        t4 = t >> 24 & 255
        return (
         t1, t2, t3, t4)

    b = col(b[0], b[5], b[10], b[15]) + col(b[4], b[9], b[14], b[3]) + col(b[8], b[13], b[2], b[7]) + col(b[12], b[1], b[6], b[11])
    return b

    # AES key expansion.

    # Specific to CN:s ten rounds. Presumes that round keys follow
    # rc(n+1) = rc(n)<<1, which isn't true generally.
def kexp(k):
    xk = [
     0] * 160
    xk[:32] = k[:32]
    cs = 32
    rc = 1
    while cs < 160:
        t = xk[cs - 4:cs]
        if cs % 32 == 0:
            t = [
             SBox[t[1]] ^ rc, SBox[t[2]], SBox[t[3]], SBox[t[0]]]
            rc *= 2
        else:
            if cs % 32 == 16:
                t = [
                 SBox[t[0]], SBox[t[1]], SBox[t[2]], SBox[t[3]]]
        xk[cs:(cs + 4)] = [
         xk[cs - 32 + 0] ^ t[0],
         xk[cs - 32 + 1] ^ t[1],
         xk[cs - 32 + 2] ^ t[2],
         xk[cs - 32 + 3] ^ t[3]]
        cs += 4

    return xk

    # expand result from initial Keccac into a 2Mb scratchad by
    # repeatedly 10 round AES:ing a chunk of data.
def asplode(kec):
    xkey = kexp(kec[:32])
    st = kec[64:192]
    xk = [ xkey[i:i + 16] for i in range(0, len(xkey), 16) ]
    pad = []
    while len(pad) < 2097152:
        for j in range(0, len(st), 16):
            t = st[j:j + 16]
            for i in range(10):
                t = round(t)
                t = [ a ^ b for a, b in zip(t, xk[i]) ]
            pad.extend(t)
        st = pad[-128:]
    return pad

    # combine final scratchpad into a single block again by xoring and
    # then 10 round AESing the blocks over each other one at a time
def implode(pad,kec):
    xkey = kexp(kec[32:64])
    xk = [ xkey[i:i + 16] for i in range(0, len(xkey), 16) ]
    st = kec[64:192]
    for p in range(0,len(pad),128):
        for i in range(128):
            st[i] ^= pad[p+i]
        for i in range(0,128,16):
            for r in range(10):
                st[i:i+16] = round(st[i:i+16])
                for j in range(16):
                    st[i+j] ^= xk[r][j]

    kec[64:192] = st
    return kec

    # Do the memhard loop. Starting two blocks, read another from scratch pad
    # do an AES round on it, xor it by some things, write it back. Then use 
    # a value from that to read another block, do two 64 bit mul:s and two
    # 64 bit adds, some more xors, and write that back. Start over and do it
    # again 1<<19 times.
def memhrd(pad, kec, variant=0, tw=[0]*8):

        # convert a series of bytes into two 64 bit words and multiply them
        # return as 8 bytes
    def mul(a, b):
        t1 = a[0] << 0 | a[1] << 8 | a[2] << 16 | a[3] << 24 | a[4] << 32 | a[5] << 40 | a[6] << 48 | a[7] << 56
        t2 = b[0] << 0 | b[1] << 8 | b[2] << 16 | b[3] << 24 | b[4] << 32 | b[5] << 40 | b[6] << 48 | b[7] << 56
        r = t1 * t2
        r1 = r >> 64
        r2 = r & 0xffffffffffffffff
        return [ r1&255, (r1>>8)&255, (r1>>16)&255, (r1>>24)&255, (r1>>32)&255, (r1>>40)&255, (r1>>48)&255, (r1>>56)&255, r2&0xff, (r2>>8)&255, (r2>>16)&255,(r2>>24)&255,  (r2>>32)&255, (r2>>40)&255, (r2>>48)&255, (r2>>56)&255 ]

        # Convert two blocks into four 64 bit numbers and pairwise add them,
        # no overflow. Swap order and convert back into bytes
    def sumhlf(a, b):
        ta1 = a[0] << 0 | a[1] << 8 | a[2] << 16 | a[3] << 24 | a[4] << 32 | a[5] << 40 | a[6] << 48 | a[7] << 56
        ta2 = a[8] << 0 | a[9] << 8 | a[10] << 16 | a[11] << 24 | a[12] << 32 | a[13] << 40 | a[14] << 48 | a[15] << 56
        tb1 = b[0] << 0 | b[1] << 8 | b[2] << 16 | b[3] << 24 | b[4] << 32 | b[5] << 40 | b[6] << 48 | b[7] << 56
        tb2 = b[8] << 0 | b[9] << 8 | b[10] << 16 | b[11] << 24 | b[12] << 32 | b[13] << 40 | b[14] << 48 | b[15] << 56
        r1,r2 = (ta1 + tb1 & 18446744073709551615, ta2 + tb2 & 18446744073709551615)
        return [ r1&255, (r1>>8)&255, (r1>>16)&255, (r1>>24)&255, (r1>>32)&255, (r1>>40)&255, (r1>>48)&255, (r1>>56)&255, r2&0xff, (r2>>8)&255, (r2>>16)&255,(r2>>24)&255,  (r2>>32)&255, (r2>>40)&255, (r2>>48)&255, (r2>>56)&255 ]

        # xor two blocks
    def blxor(a, b):
        return [ t1 ^ t2 for t1, t2 in zip(a, b) ]

        # pull 17 bits from a block for use as an address in the scratchpad.
        # Zeroes out the 4 LSB rather than dividing, making it useful as an
        # index in the pad directly. >>4 instead of &.. would give a block
        # index, which could then later be <<4 to give an actual location.
    def toaddr(a):
        return (a[2] << 16 | a[1] << 8 | a[0]) & 2097136

        # make the first two indexes
    A = blxor(kec[0:16], kec[32:48])
    B = blxor(kec[16:32], kec[48:64])

    for i in range(1<<19):
        t = toaddr(A)
        C = pad[t:t + 16]
        C = round(C)
        C = blxor(C, A)
        pad[t:(t + 16)] = blxor(B, C)

            # After the Apr 2018 hardfork, this will be/was
            # added to the loop. This is equivalent to VARIANT1_1
            # in the original C. 
        if variant:
            a = pad[t+11]
            a = (~a&1)<<4 | ((~a&1)<<4 & a)<<1 | (a&32)>>1
            pad[t+11] ^= a

        B = C
        t = toaddr(C)
        C = pad[t:t + 16]

        P = mul(B, C)
        A = sumhlf(A, P)
        pad[t:(t + 16)] = A
            # this is the second variant add in, equivalent of VARIENT1_2 in
            # C. 
        if variant:
            for i in range(8):
                pad[t+i+8] ^= tw[i]
        A = blxor(A, C)

    return pad

    # Calculate 1600 bit keccak hash from a 200b input. 
    # This isn't equivalent to the final SHA3 version.
    # I don't remember how exactly, but don't expect it to be.
def keccak(inp):
    def rol(b,n):
        return ((b<<n) & 0xffffffffffffffff) | (b>>(64-n))

    s = [sum(a[i]<<(i<<3) for i in range(8)) for a in [inp[i:i+8] for i in range(0,200,8)]]

    xo = [ 0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008 ]

    ro = [ 1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14, 
           27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44 ]

    pn = [ 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 
           15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 ]

    for r in range(24):
        b0 = s[0]^s[5]^s[10]^s[15]^s[20]
        b1 = s[1]^s[6]^s[11]^s[16]^s[21]
        b2 = s[2]^s[7]^s[12]^s[17]^s[22]
        b3 = s[3]^s[8]^s[13]^s[18]^s[23]
        b4 = s[4]^s[9]^s[14]^s[19]^s[24]

        t = b4 ^ rol(b1,1)
        s[0] ^=t ; s[5] ^=t ; s[10] ^=t ; s[15] ^=t ; s[20] ^=t
        t = b0 ^ rol(b2,1)
        s[1] ^=t ; s[6] ^=t ; s[11] ^=t ; s[16] ^=t ; s[21] ^=t
        t = b1 ^ rol(b3,1)
        s[2] ^=t ; s[7] ^=t ; s[12] ^=t ; s[17] ^=t ; s[22] ^=t
        t = b2 ^ rol(b4,1)
        s[3] ^=t ; s[8] ^=t ; s[13] ^=t ; s[18] ^=t ; s[23] ^=t
        t = b3 ^ rol(b0,1)
        s[4] ^=t ; s[9] ^=t ; s[14] ^=t ; s[19] ^=t ; s[24] ^=t

        t = s[1]
        for i in range(24):
            j = pn[i]
            t2 = s[j]
            s[j] = rol(t, ro[i])
            t = t2

        for j in range(0,24,5):
            b0 = s[j    ];
            b1 = s[j + 1];
            b2 = s[j + 2];
            b3 = s[j + 3];
            b4 = s[j + 4];
            s[j    ] ^= (b1^0xffffffffffffffff) & b2;
            s[j + 1] ^= (b2^0xffffffffffffffff) & b3;
            s[j + 2] ^= (b3^0xffffffffffffffff) & b4;
            s[j + 3] ^= (b4^0xffffffffffffffff) & b0;
            s[j + 4] ^= (b0^0xffffffffffffffff) & b1;

        s[0] ^= xo[r]

    b = reduce(lambda a,b:a+b,[[((a>>(c<<3))&255) for c in range(8)] for a in s])
    return b


def blake(data):
    """
    Blake hash. Assumes 200b input, produces 32b output
    :param data:
    :return:
    """
    K = [
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
        0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
    ]
    h = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ]
    S = blakeS # Constant from bottom of file
    data = data+[0x80] + [0x00]*46 + [0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x40]
    for (o,t) in [(0,512), (64,1024), (128,1536), (192,1600)]:
        m = [ ((data[o+i+0]<<24))|
               ((data[o+i+1]<<16))|
               ((data[o+i+2]<<8))|
               ((data[o+i+3]<<0)) for i in range(0,64,4)]
        v = [0]*16
        v[ 0: 8] = [h[i] for i in range(8)]
        v[ 8:16] = [K[i] for i in range(8)]
        v[ 8:12] = [v[8+i] for i in range(4)]
        v[12] = v[12] ^ t
        v[13] = v[13] ^ t

        ror = lambda x,n: (x >> n) | ((x << (32-n)) & 0xFFFFFFFF)
        for inner_round in range(14):
            i = 0
            for (a, b, c, d) in [
                ( 0, 4, 8,12), ( 1, 5, 9,13), ( 2, 6,10,14),
                ( 3, 7,11,15), ( 0, 5,10,15), ( 1, 6,11,12),
                ( 2, 7, 8,13), ( 3, 4, 9,14) ]:
                p,q  = S[inner_round][i], S[inner_round][i+1]
                i += 2

                v[a] = ((v[a] + v[b]) + (m[p] ^ K[q]) ) & 0xFFFFFFFF
                v[d] = ror( v[d] ^ v[a], 16)
                v[c] = (v[c] + v[d]) & 0xFFFFFFFF
                v[b] = ror( v[b] ^ v[c], 12)

                v[a] = ((v[a] + v[b]) + (m[q] ^ K[p]) ) & 0xFFFFFFFF
                v[d] = ror( v[d] ^ v[a], 8)
                v[c] = (v[c] + v[d]) & 0xFFFFFFFF
                v[b] = ror( v[b] ^ v[c], 7)
                
        h = [h[i]^v[i]^v[i+8] for i in range(8)]
    rv = reduce(lambda a,b:a+b,[[(h[i]>>24)&255, (h[i]>>16)&255, (h[i]>>8)&255, (h[i]>>0)&255] for i in range(8)])
    return rv


def _debug_blake_demo():
    """Legacy ad-hoc debug routine, intentionally not executed on import."""
    import hashlib

    values = [
        b'98231978eaff98231978eaffa98231978eaff98231978eaffa98231978eaff98231978eaffa98231978eaff98231978eaffa',
        b'98231978eaff98231978eaffa98231978eaff98231978eaffa98231978eaff98231978eaffa98231978eaff98231978eaffa'
    ]

    concat = (int.from_bytes(values[0], byteorder="little") << 8 * 100) + int.from_bytes(values[1], byteorder="little")
    x = concat.to_bytes(length=200, byteorder="little")
    print(len(list(x)))
    y = blake(list(x))
    print(y)
    print(len(y))

    print('-' * 44)

    def blake2b_256(data):
        hash_obj = hashlib.blake2b(data, digest_size=32)
        return hash_obj.digest()

    def blake2b_512(data):
        hash_obj = hashlib.blake2b(data, digest_size=64)
        return hash_obj.digest()

    data = b"Hello, world!"
    hashed_data = blake2b_256(data)
    print("Hashed data:", hashed_data.hex())
    print(len('b5da441cfe72ae042ef4d2b17742907f675de4da57462d4c3609c2e2ed755970'))

    hashed_data = blake2b_512(data)
    print("Hashed data:", hashed_data.hex())
    print(len('a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f'))


    # Groestl hash. Assumes 200b input, produces 32b output
def groestl(inp):
    def col(x,y,i,c0,c1,c2,c3,c4,c5,c6,c7):
        T = groestlT # Constant from bottom of file
        y[i] = T[0*256+((x[c0]>>0 )&255)] ^ T[1*256+((x[c1]>>8 )&255)] ^ T[2*256+((x[c2]>>16)&255)] ^ T[3*256+((x[c3]>>24)&255)] ^ T[4*256+((x[c4]>>0 )&255)] ^ T[5*256+((x[c5]>>8 )&255)] ^ T[6*256+((x[c6]>>16)&255)] ^ T[7*256+((x[c7]>>24)&255)]

    def P(x,y,r):
        x[ 0] ^= 0x00000000^r
        x[ 2] ^= 0x00000010^r
        x[ 4] ^= 0x00000020^r
        x[ 6] ^= 0x00000030^r
        x[ 8] ^= 0x00000040^r
        x[10] ^= 0x00000050^r
        x[12] ^= 0x00000060^r
        x[14] ^= 0x00000070^r
        col(x,y, 0,  0,  2,  4,  6,  9, 11, 13, 15)
        col(x,y, 1,  9, 11, 13, 15,  0,  2,  4,  6)
        col(x,y, 2,  2,  4,  6,  8, 11, 13, 15,  1)
        col(x,y, 3, 11, 13, 15,  1,  2,  4,  6,  8)
        col(x,y, 4,  4,  6,  8, 10, 13, 15,  1,  3)
        col(x,y, 5, 13, 15,  1,  3,  4,  6,  8, 10)
        col(x,y, 6,  6,  8, 10, 12, 15,  1,  3,  5)
        col(x,y, 7, 15,  1,  3,  5,  6,  8, 10, 12)
        col(x,y, 8,  8, 10, 12, 14,  1,  3,  5,  7)
        col(x,y, 9,  1,  3,  5,  7,  8, 10, 12, 14)
        col(x,y,10, 10, 12, 14,  0,  3,  5,  7,  9)
        col(x,y,11,  3,  5,  7,  9, 10, 12, 14,  0)
        col(x,y,12, 12, 14,  0,  2,  5,  7,  9, 11)
        col(x,y,13,  5,  7,  9, 11, 12, 14,  0,  2)
        col(x,y,14, 14,  0,  2,  4,  7,  9, 11, 13)
        col(x,y,15,  7,  9, 11, 13, 14,  0,  2,  4)
      
    def Q(x,y,r):
        x[ 0] = x[ 0] ^ 0xffffffff
        x[ 1] ^= 0xffffffff^r
        x[ 2] = x[ 2] ^ 0xffffffff
        x[ 3] ^= 0xefffffff^r
        x[ 4] = x[ 4] ^ 0xffffffff
        x[ 5] ^= 0xdfffffff^r
        x[ 6] = x[ 6] ^ 0xffffffff
        x[ 7] ^= 0xcfffffff^r
        x[ 8] = x[ 8] ^ 0xffffffff
        x[ 9] ^= 0xbfffffff^r
        x[10] = x[10] ^ 0xffffffff
        x[11] ^= 0xafffffff^r
        x[12] = x[12] ^ 0xffffffff
        x[13] ^= 0x9fffffff^r
        x[14] = x[14] ^ 0xffffffff
        x[15] ^= 0x8fffffff^r
        col(x,y, 0,  2,  6, 10, 14,  1,  5,  9, 13)
        col(x,y, 1,  1,  5,  9, 13,  2,  6, 10, 14)
        col(x,y, 2,  4,  8, 12,  0,  3,  7, 11, 15)
        col(x,y, 3,  3,  7, 11, 15,  4,  8, 12,  0)
        col(x,y, 4,  6, 10, 14,  2,  5,  9, 13,  1)
        col(x,y, 5,  5,  9, 13,  1,  6, 10, 14,  2)
        col(x,y, 6,  8, 12,  0,  4,  7, 11, 15,  3)
        col(x,y, 7,  7, 11, 15,  3,  8, 12,  0,  4)
        col(x,y, 8, 10, 14,  2,  6,  9, 13,  1,  5)
        col(x,y, 9,  9, 13,  1,  5, 10, 14,  2,  6)
        col(x,y,10, 12,  0,  4,  8, 11, 15,  3,  7)
        col(x,y,11, 11, 15,  3,  7, 12,  0,  4,  8)
        col(x,y,12, 14,  2,  6, 10, 13,  1,  5,  9)
        col(x,y,13, 13,  1,  5,  9, 14,  2,  6, 10)
        col(x,y,14,  0,  4,  8, 12, 15,  3,  7, 11)
        col(x,y,15, 15,  3,  7, 11,  0,  4,  8, 12)

    def F(h,m):
        Ptmp = [0]*16;
        Qtmp = [0]*16;
        y = [0]*16;
        z = [0]*16;

        for i in range(16):
            z[i] = m[i]
            Ptmp[i] = h[i]^m[i]

        Q(z, y, 0x00000000)
        Q(y, z, 0x01000000)
        Q(z, y, 0x02000000)
        Q(y, z, 0x03000000)
        Q(z, y, 0x04000000)
        Q(y, z, 0x05000000)
        Q(z, y, 0x06000000)
        Q(y, z, 0x07000000)
        Q(z, y, 0x08000000)
        Q(y, Qtmp, 0x09000000)

        P(Ptmp, y, 0x00000000)
        P(y, z, 0x00000001)
        P(z, y, 0x00000002)
        P(y, z, 0x00000003)
        P(z, y, 0x00000004)
        P(y, z, 0x00000005)
        P(z, y, 0x00000006)
        P(y, z, 0x00000007)
        P(z, y, 0x00000008)
        P(y, Ptmp, 0x00000009)

        for i in range(16):
            h[i] ^= Ptmp[i]^Qtmp[i]

    buf = [0]*16
    tmp = [0]*16
    y = [0]*16
    z = [0]*16
    d = [0]*16

    d[15] = 0x00010000
    data = [
        (inp[i+3]<<24)| (inp[i+2]<<16)| (inp[i+1]<<8)| (inp[i+0]<<0) 
        for i in range(0,len(inp),4) ] + [0x80] + [0]*12 + [4<<24]

    F(d,data[0:16])
    F(d,data[16:32])
    F(d,data[32:48])
    F(d,data[48:64])

    tmp = d[:16]
    P(tmp, y, 0x00000000)
    P(y, z, 0x00000001)
    P(z, y, 0x00000002)
    P(y, z, 0x00000003)
    P(z, y, 0x00000004)
    P(y, z, 0x00000005)
    P(z, y, 0x00000006)
    P(y, z, 0x00000007)
    P(z, y, 0x00000008)
    P(y, tmp, 0x00000009)

    rv = [d[j] ^ tmp[j] for j in range(8,16)]
    rv = reduce(lambda a,b:a+b,[[a&255,(a>>8)&255, (a>>16)&255, (a>>24)&255] for a in rv])
    return rv

    # JH hash, Assumes 200b input, produces 32b output
def jh(data):
    hashval = [32]
    A = [0]*256
    rc = [0]*64
    rcx = [0]*256
    tmp = [0]*256
    S = [[9,0,4,11,13,12,3,15,1,10,2,6,7,5,8,14],[3,12,6,13,5,7,1,9,15,2,0,4,11,10,14,8]] 
    rc0 = [0x6,0xa,0x0,0x9,0xe,0x6,0x6,0x7,0xf,0x3,0xb,0xc,0xc,0x9,0x0,0x8,0xb,0x2,0xf,0xb,0x1,0x3,0x6,0x6,0xe,0xa,0x9,0x5,0x7,0xd,0x3,0xe,0x3,0xa,0xd,0xe,0xc,0x1,0x7,0x5,0x1,0x2,0x7,0x7,0x5,0x0,0x9,0x9,0xd,0xa,0x2,0xf,0x5,0x9,0x0,0xb,0x0,0x6,0x6,0x7,0x3,0x2,0x2,0xa]
    d = [254,0,64,128,255,254] 

    H = [1]+[0]*127

    for b in d:
        if b<=128:
            for i in range(64):
                H[i] ^= data[b+i]
        elif b==255:
            H[:8] = [H[i]^data[192+i] for i in range(8)]
            H[8] ^= 128
        rc = rc0[:]

        for i in range(256):
            t0 = (H[i>>3] >> (7 - (i & 7)) ) & 1
            t1 = (H[(i+256)>>3] >> (7 - (i & 7)) ) & 1
            t2 = (H[(i+512 )>>3] >> (7 - (i & 7)) ) & 1
            t3 = (H[(i+768 )>>3] >> (7 - (i & 7)) ) & 1
            tmp[i] = (t0 << 3) | (t1 << 2) | (t2 << 1) | (t3 << 0)
        for i in range(128):
            A[i << 1] = tmp[i]
            A[(i << 1)+1] = tmp[i+128]

        for r in range(42):
            for i in range(256):
                rcx[i] = (rc[i >> 2] >> (3 - (i & 3)) ) & 1
            for i in range(256):
                tmp[i] = S[rcx[i]][A[i]]
            for i in range(0,256,2):
                t0 = tmp[i+1]^(((tmp[i]<<1)^(tmp[i]>>3)^((tmp[i]>>2)&2))&0xf)
                t1 = tmp[i+0]^(((t0<<1)^(t0>>3)^((t0>>2)&2))&0xf)
                t2 = (i>>1)&1
                tmp[i+t2^1] = t0
                tmp[i+t2] = t1
            for i in range(128):
                A[i] = tmp[i<<1] 
                A[(i+128)^1] = tmp[(i<<1)+1] 
            for i in range(64):
                tmp[i] = S[0][rc[i]]
            for i in range(0,64,2):
                tmp[i+1] ^= ((tmp[i]<<1)^(tmp[i]>>3)^((tmp[i]>>2)&2))&0xf
                tmp[i] ^= ((tmp[i+1]<<1)^(tmp[i+1]>>3)^((tmp[i+1]>>2)&2))&0xf
            for i in range(0,64,4):
                t = tmp[i+2]
                tmp[i+2] = tmp[i+3]
                tmp[i+3] = t
            for i in range(32):
                rc[i] = tmp[i<<1]  
                rc[(i+32)^1] = tmp[(i<<1)+1]

        for i in range(128):
            tmp[i] = A[i << 1]
            tmp[i+128] = A[(i << 1)+1]
        for i in range(128):
            H[i] = 0
        for i in range(256):
            t0 = (tmp[i] >> 3) & 1
            t1 = (tmp[i] >> 2) & 1
            t2 = (tmp[i] >> 1) & 1
            t3 = (tmp[i] >> 0) & 1
            H[i>>3] |= t0 << (7 - (i & 7))
            H[(i + 256)>>3] |= t1 << (7 - (i & 7))
            H[(i + 512)>>3] |= t2 << (7 - (i & 7))
            H[(i + 768)>>3] |= t3 << (7 - (i & 7))

        if b<=128:
            for i in range(64):
                H[i+64] ^= data[b+i]
        elif(b==255):
            for i in range(8):
                H[64+i] ^= data[192+i]
            H[8+64] ^= 128
            H[63] ^= 64
            H[62] ^= 6 
    H[127] ^= 64
    H[126] ^= 6
    return H[96:]

    # Skein hash. Assumes 200b input, produces 32b output
def skein(data):
    def M(x): # Mask down to 64 bin
        return x & 0xffffffffffffffff
    def R64(x, p, n): # Rotate left, 64 bit
        x[p] = M((x[p] << n) | (x[p] >> (64-n)))
    def Add(x, a, b): # 64 bit add, no overflow
        x[a] = M(x[a]+x[b])

    def R512(X,p0,p1,p2,p3,p4,p5,p6,p7,q):
        Rk = [ [46, 36, 19, 37], [33, 27, 14, 42], [17, 49, 36, 39], [44,  9, 54, 56], [39, 30, 34, 24], [13, 50, 10, 17], [25, 29, 39, 43], [ 8, 35, 56, 22]]
        
        Add(X,p0,p1)
        R64(X,p1,Rk[q][0])
        X[p1] ^= X[p0] 

        Add(X,p2,p3)
        R64(X,p3,Rk[q][1])
        X[p3] ^= X[p2]

        Add(X,p4,p5)
        R64(X,p5,Rk[q][2])
        X[p5] ^= X[p4]

        Add(X,p6,p7)
        R64(X,p7,Rk[q][3])
        X[p7] ^= X[p6] 

        # Skein types and lengths. Since it's just five blocks, always
        # same length and such, they're constant. Here as TYPE | LEN,
        # as it is stored in Skeins T(2)
    LC = [ 0x7000000000000040, 0x3000000000000080, 0x30000000000000c0,
        0xb0000000000000c8, 0xff00000000000008 ]
        # Init vector. Specific to 512-256 hash
    L = [ 0,0,0, 0xCCD044A12FDB3E13, 0xE83590301A79A9EB,
          0x55AEA0614F816E6F, 0x2A2767A4AE9B94DB, 0xEC06025E74DD7683,
          0xE7A436CDC4746251, 0xC36FBAF9393AD185, 0x3EEDBA1833EDFC13, 0]
        # Keeper of data. Extra length so that after the 200b we send,
        # there's enough zeros for another full block, and, for the
        # OUT+FINAL block, one with all zeros. 
    b = [0]*35
        # Offset to current data. Hops around
    w = 0
        # Temp state data
    X = [0]*8;
        # fill b up with 8b words
    for i in range(25):
        b[i] = ( 
            (data[(i*8)+0]<<0)|
            (data[(i*8)+1]<<8)|
            (data[(i*8)+2]<<16)|
            (data[(i*8)+3]<<24)|
            (data[(i*8)+4]<<32)|
            (data[(i*8)+5]<<40)|
            (data[(i*8)+6]<<48)|
            (data[(i*8)+7]<<56))
        # Each block..
    for i in range(5): 
            # T2 = T1^T0, like we stored
        L[2] = LC[i]
            # T0 = length. Extract with &0xff
        L[0] = L[2]&255; 
            # T2 = type+flags. Exract by removing T0
        L[1] = L[2]^L[0];
            # Parity + magic constant.
        L[11] = L[3]^L[4]^L[5]^L[6]^L[7]^L[8]^L[9]^L[10]^0x1BD11BDAA9FC1A22;
            # Next chunk
        w = ((i&3)<<3)+25*(i>>2);
            # Init X
        for R in range(8):
            X[R]= M(b[w+R] + L[R+3])
        X[5]=M(X[5]+L[0])
        X[6]=M(X[6]+L[1])

            # Rounds
        for R in range(0,18,2):
            R512(X,0,1,2,3,4,5,6,7,0)
            R512(X,2,1,4,7,6,5,0,3,1)
            R512(X,4,1,6,3,0,5,2,7,2)
            R512(X,6,1,0,7,2,5,4,3,3)
            for j in range(8):
                X[j] = M(X[j]+L[3+((R+j+1)%9)])
            X[5] = M(X[5]+L[(R+1)%3])
            X[6] = M(X[6]+L[(R+2)%3])
            X[7] = M(X[7]+R+1)
            R512(X,0,1,2,3,4,5,6,7,4)
            R512(X,2,1,4,7,6,5,0,3,5)
            R512(X,4,1,6,3,0,5,2,7,6)
            R512(X,6,1,0,7,2,5,4,3,7)
            for j in range(8):
                X[j] = M(X[j]+L[3+((R+j+2)%9)])
            X[5] = M(X[5]+L[(R+2)%3])
            X[6] = M(X[6]+L[(R+3)%3])
            X[7] = M(X[7]+R+2)

            # Back into state w/ round results
        for R in range(8):
            L[3+R] = X[R] ^ b[w+R] 

        # Done, convert to bytes and shove into h
    h = []
    for i in range(4):
        h.extend( [
            (L[i+3]>>0)&255,
            (L[i+3]>>8)&255,
            (L[i+3]>>16)&255,
            (L[i+3]>>24)&255,
            (L[i+3]>>32)&255,
            (L[i+3]>>40)&255,
            (L[i+3]>>48)&255,
            (L[i+3]>>56)&255] )

    return h

    # All of the preceeding hash functions are de-generalized to presume
    # input length and to only produce specific output length. The will not
    # function correctly under other circumstances.
   

    # The main cryptonight hash function. Takes 76 bytes input (without
    # verifying that) and outputs the final 32 byte hash. Both input
    # and output are arrays of 8 bit integers. If "quiet" is set False,
    # it'll print what it's doing through off and on the steps. If
    # "variant" is set to 1, it'll work as it's supposed to after the
    # Apr 2018 hard fork, otherwise as it's supposed to before.
def cn_slow_hash(inp,quiet=0,variant=0):
    tw = [0]*8 
    if(not quiet):
        print("Keccac..")
        # Padding
    inp = inp + [0x01] + [0x00]*58 + [0x80] + [0x00]*64
    kec = keccak(inp)

        # Equivalent to VARIANT*INIT* in C. Stores the last 8 bytes after
        # keccak xor the current Nonce, which will later be xored in thoughout
        # the memhard loop (in the equivalent of VARIANT1_2).
    if variant:
        tw = [a^b for (a,b) in zip(kec[192:],inp[35:35+8])]

    if(not quiet):
        print("Expanding scratchpad..")
    pad = asplode(kec)
    if(not quiet):
        print("Memhard..")
    memhrd(pad, kec, variant, tw)
    if(not quiet):
        print("Imploding..")
    imp = implode(pad, kec)
    if(not quiet):
        print("Keccac again..")
    kec = keccak(imp)

    h = kec[0]&3
    if h==0:
        if(not quiet):
            print("Blake..")
        r = blake(kec)
    elif h==1:
        if(not quiet):
            print("Groestl..")
        r = groestl(kec)
    elif h==2:
        if(not quiet):
            print("Jh..")
        r = jh(kec)
    else:
        if(not quiet):
            print("Skein..")
        r = skein(kec)

    return r


def slow_hash_glue_func(output_buffer, inp_data_intli_form, input_len):
    tmp_res = cn_slow_hash(inp_data_intli_form, quiet=1, variant=1)
    for k in range(len(output_buffer)):  # regular copy
        output_buffer[k] = tmp_res[k]


import time # only used in main

    # run_tests(). This runs a single case and checks it against one of two
    # precalculated results depending on "variant". This isn't particularly
    # sufficient for testing it, but it's at least a single runnable example

def run_tests():
    inp = [
        0x05, 0x05, 0x84, 0xe2, 0xfa, 0xcc, 0x05, 0xfe, 
        0x5c, 0x31, 0x96, 0xe9, 0x95, 0xae, 0x88, 0x31, 
        0x0b, 0xa8, 0x6e, 0xae, 0x4a, 0xb6, 0x25, 0xab, 
        0xd2, 0x6e, 0x19, 0x2f, 0x26, 0xf3, 0x2c, 0x7d, 
        
        0xcb, 0x6d, 0xb1, 0xd1, 0x08, 0xd7, 0x68, 0x5d, 
        0x00, 0x08, 0x57, 0xd6, 0x62, 0xea, 0x60, 0x02, 
        0xe5, 0x19, 0xa2, 0x76, 0xb9, 0xd6, 0x9a, 0xb9,
        0xf0, 0xdf, 0x14, 0xc9, 0xf5, 0x86, 0xe1, 0x1a,

        0xe4, 0x57, 0xb1, 0xb5, 0x74, 0x05, 0xaf, 0xbf, 
        0x9c, 0xc0, 0xcb, 0x06 ]

    st = time.time()
    variant = 1 # change to run other version

    r = cn_slow_hash(inp, False, variant)

    et = time.time()

    print(' '.join("%.2x"%(a) for a in r))
    print("Total %ds (%f H/s)"%(et-st, 1./(et-st)))
    correct_result_old = [0x2a,0x26,0x47,0x75,0x7c,0xf6,0x20,0xa9,0x9a,0xf4,0xf8,0x3f,0xe5,0x9f,0x98,0x5d,0x3e,0x3b,0x8d,0x63,0xa7,0x5e,0x01,0x20,0x75,0x6f,0x8b,0xff,0xa4,0x8e,0x00,0x00]
    correct_result_new = [0xfc,0x24,0x23,0x8f,0x96,0x0c,0x14,0x72,0x73,0x86,0x29,0x5b,0xd0,0xfc,0xec,0xba,0xce,0x8f,0x2a,0xef,0x74,0xad,0x71,0x08,0x77,0x1c,0x7c,0x83,0x2b,0x0a,0x9f,0x00]

    if variant:
        print("Pass" if correct_result_new==r else "Fail")
    else:
        print("Pass" if correct_result_old==r else "Fail")


if __name__ == '__main__':
    run_tests()
