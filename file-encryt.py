from hashlib import md5
from opcode import opname
from Crypto.Cipher import AES
from os import urandom
import hashlib
import sys
import binascii
import Padding
import pyaes, pbkdf2, os, secrets

passwordSalt=b')\x0b\xeb:\xa9\xf7\xb0\xeb!\xc6hg^W\x07\xca'
bs = AES.block_size
salt_ = urandom(bs) 

def derive_key_and_iv(password, salt, key_length, iv_length): #derive key and IV from password and salt.
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

#ECB-MODE
def encrypt_file_ecb(in_file,out_file,password):
    key_ = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    finished= False
    cipher =AES.new(key_,AES.MODE_ECB)
    while not finished:
        chunk = in_file.read(1024*bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))
    print("Successfull!!!")           
    
def decrypt_file_ecb(in_file,out_file,password):
    key_ = pbkdf2.PBKDF2(password, passwordSalt).read(32)    
    cipher = AES.new(key_, AES.MODE_ECB)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk))
    print("Successfull!!!")

#CTR-MODE
def encrypt_file_ctr(filename,password):   
    plaintext=open(filename,encoding='utf8').read()
    iv_= secrets.randbits(256)
    key_= pbkdf2.PBKDF2(password,passwordSalt).read(32)
    print(key_)
    aes = pyaes.AESModeOfOperationCTR(key_, pyaes.Counter(iv_))
    ciphertext=aes.encrypt(plaintext)
    output_file = filename.replace('.txt','_encryted.txt')
    with open(output_file, 'wb') as f:
        f.write(binascii.hexlify(ciphertext))
    print("Successful !!!. Save in", output_file)
    print("Your IV:",iv_)

def decrypt_file_ctr(filename,password,iv_):
    key_ = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    print(key_)
    aes= pyaes.AESModeOfOperationCTR(key_, pyaes.Counter(iv_))
    byteStr=open(filename).read()
    ciphertext=binascii.unhexlify(byteStr)
    decrypted=aes.decrypt(ciphertext)
    output_file=filename.replace('_encrypted.txt','_decrypted.txt')
    with open(output_file,'wb') as f:
        f.write(decrypted)
    print("Successful !!!. Save in ", output_file)

# CBC-MODE
def encrypt(in_file, out_file, password, key_length=32):
    key, iv = derive_key_and_iv(password, salt_, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt_)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs) 
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))
    print("Successfull!!!")
    
def decrypt(in_file, out_file, password, key_length=32):
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk))
    print("Successfull!!!")
    
# OFB-MODE
def encrypt_file_ofb(in_file, out_file, password, key_length=32):
    key, iv = derive_key_and_iv(password, salt_, key_length, bs)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    out_file.write(salt_)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs) 
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))
    print("Successfull!!!")
    
def decrypt_file_ofb(in_file, out_file, password, key_length=32):
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk))
    print("Successfull!!!")
    
# CFB-MODE
def encrypt_file_cfb(in_file, out_file, password, key_length=32):
    key, iv = derive_key_and_iv(password, salt_, key_length, bs)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    out_file.write(salt_)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs) 
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))
    print("Successfull!!!")
    
def decrypt_file_cfb(in_file, out_file, password, key_length=32):
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk))
    print("Successfull!!!")
######MENU######
option=input("---ENCRYPT/DECRYPT WITH AES---\nChoose your option:\n1. Encrypt File\n2. Decrypt File\nYour option: ")
if option == '1':
    name1=input("Your file you want to encrypt:\n")
    name2=input("Your encrypted file:\n")
    password=input("Your secret key:\n")
    opt=input("Choose your mode encrypt:\n1. Encrypt ECB mode\n2. Encrypt CBC mode\n3. Encrypt CFB mode\n4. Encrypt OFB mode\n5. Encrypt CTR mode\nYour selection: ")
    if opt=='1':
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt_file_ecb(in_file, out_file, password)
    if opt== '2':
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt(in_file, out_file, password)
    if opt== '3':
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt_file_cfb(in_file, out_file, password)
    if opt== '4':
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt_file_ofb(in_file, out_file, password)
    elif opt=='5':
        encrypt_file_ctr(name1,password)
elif option == '2':
    name1=input("Your file you want to decrypt:\n")
    name2=input("Your decrypted file:\n")
    password=input("Your secret key:\n")  
    opt=input("Choose your mode decrypt:\n1. Decrypt ECB mode\n2. Decrypt CBC mode\n3. Decrypt CFB mode\n4. Decrypt OFB mode\n5. Decrypt CTR mode\nYour selection: ")
    if opt=='1':
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt_file_ecb(in_file, out_file, password)      
    elif opt=='2':
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt(in_file, out_file, password)
    elif opt=='3':
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt_file_cfb(in_file, out_file, password)
    elif opt=='4':     
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt_file_ofb(in_file, out_file, password)
    elif opt=='5':
        iv=int(input('Your IV:'))
        decrypt_file_ctr(name1,password,iv)

        




