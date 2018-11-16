#!/usr/bin/python3
# -*- mode: python; coding: utf-8 -*

"""
auther  :   d0ller
mail    :   fantasistadoller@gmail.com

This Source Code is Public Domain.

Please see and follow pycrypto Lisences.
https://github.com/dlitz/pycrypto/blob/master/COPYRIGHT

"""

from Crypto.Cipher import AES
from binascii import hexlify
from math import ceil

class CMAC:

    def _xor(self,a,b):
        result = b""
        for i in range(len(a)):
            result += (a[i]^b[i]).to_bytes(1,"big")
        return result

    def _e(self,key,plain):
        aes = AES.new(key)
        return aes.encrypt(plain)

    def _d(self,key,enc):
        aes = AES.new(key)
        return aes.decrypt(enc)

    def generate_subkey(self,k): #RFC4493 Figure 2.2.
        const_zero = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        const_rb = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87"

        #Step 1
        l = self._e(k,const_zero)

        #Step 2
        if (l[0] & 0b10000000) == 0:
            k1 = (int.from_bytes(l,"big") << 1).to_bytes(16,"big")
        else:
            k1 = self._xor(((int.from_bytes(l,"big") << 1).to_bytes(17,"big"))[1:],const_rb) #Use lower 16-octet to calc XOR

        #Step 3
        if (k1[0] & 0b10000000) == 0:
            k2 = (int.from_bytes(k1,"big") << 1).to_bytes(16,"big")
        else:
            k2 = self._xor(((int.from_bytes(k1,"big") << 1).to_bytes(17,"big"))[1:],const_rb) #Use lower 16-octet to calc XOR

        #Step 4
        return k1,k2


    def aes_cmac(self,k,m): #RFC4493 Figure2.3.
        const_zero = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        const_bsize = 16

        #Step 1
        k1,k2 = self.generate_subkey(k)

        #Step 2
        n = ceil(len(m)/const_bsize)

        #generate Message Block
        m_block = []
        for i in range(n):
            m_block.append(m[const_bsize*i:const_bsize*(i+1)])

        #Step 3
        if n == 0:
            n = 1
            m_block.append(b"")
            flag = False
        else:
            if (len(m) % const_bsize) == 0:
                flag = True
            else:
                flag = False

        #Step 4
        if flag == True:
            m_last = self._xor(m_block[n-1],k1)
        else:
            padding = b"\x80" + b"\x00"*(const_bsize - len(m_block[n-1]) - 1 ) # b"\x80" equals 0b10000000
            m_last = self._xor((m_block[n-1] + padding),k2)

        #Step 5
        x = const_zero

        #Step 6
        for i in range(n-1):
            y = self._xor(x,m_block[i])
            x = self._e(k,y)
        y = self._xor(m_last,x)
        t = self._e(k,y)

        #Step 7
        return t

if __name__ == '__main__':

    #Test Vectors
    k  = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
    
    m1 = b"" 

    m2 = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"

    m3 = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" \
         b"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" \
         b"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11"

    m4 = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a" \
         b"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51" \
         b"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef" \
         b"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"

    c = CMAC()

    k1,k2 = c.generate_subkey(k)

    print("k1 : %s" % hexlify(k1))
    print("k2 : %s\n" % hexlify(k2))

    t1 = c.aes_cmac(k,m1)
    print("t1 : %s" % hexlify(t1))

    t2 = c.aes_cmac(k,m2)
    print("t2 : %s" % hexlify(t2))
    
    t3 = c.aes_cmac(k,m3)
    print("t3 : %s" % hexlify(t3))

    t4 = c.aes_cmac(k,m4)
    print("t4 : %s" % hexlify(t4))
