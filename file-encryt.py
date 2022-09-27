from hashlib import md5
from opcode import opname
from Crypto.Cipher import AES
from os import urandom
import hashlib
import sys
import binascii
import Padding
import pyaes, pbkdf2, os, secrets

def derive_key_and_iv(password, salt, key_length, iv_length): #derive key and IV from password and salt.
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

#ECB-MODE
def encrypt_ecb(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def  decrypt_ecb(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))

#CBC,CFB,OFB-MODE
def encrypt_2(plaintext,key, mode,iv):
	encobj = AES.new(key,mode,iv)
	return(encobj.encrypt(plaintext))

def decrypt_2(ciphertext,key, mode,iv):
	encobj = AES.new(key,mode,iv)
	return(encobj.decrypt(ciphertext))

#CTR-MODE
def encrypt_ctr_aes256(plaintext,password):
    passwordSalt=b')\x0b\xeb:\xa9\xf7\xb0\xeb!\xc6hg^W\x07\xca'
    iv = secrets.randbits(256)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext = aes.encrypt(plaintext)
    print('Encrypted:', binascii.hexlify(ciphertext).decode())
    print('Your IV:' ,iv)

def decrypt_ctr_aes256(cipher,password,iv):
    passwordSalt=b')\x0b\xeb:\xa9\xf7\xb0\xeb!\xc6hg^W\x07\xca'
    cipher_ = bytes.fromhex(cipher)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    aes= pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted=aes.decrypt(cipher_).decode()
    print('Decrypted:', decrypted)
    
###---FILE---###
# CTR-MODE
def encrypt_file_ctr(filename,password):  
    passwordSalt=b')\x0b\xeb:\xa9\xf7\xb0\xeb!\xc6hg^W\x07\xca'
    plaintext=open(filename,encoding='utf8').read()
    iv= secrets.randbits(256)
    key= pbkdf2.PBKDF2(password,passwordSalt).read(32)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext=aes.encrypt(plaintext)
    output_file = filename.replace('.txt','_encryted.txt')
    with open(output_file, 'wb') as f:
        f.write(binascii.hexlify(ciphertext))
    print("Successful !!!. Save in", output_file)
    print("Your IV:",iv)

def decrypt_file_ctr(filename,password,iv):
    passwordSalt=b')\x0b\xeb:\xa9\xf7\xb0\xeb!\xc6hg^W\x07\xca'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    aes= pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    byteStr=open(filename).read()
    ciphertext=binascii.unhexlify(byteStr)
    decrypted=aes.decrypt(ciphertext)
    output_file=filename.replace('_encrypted.txt','_decrypted.txt')
    with open(output_file,'wb') as f:
        f.write(decrypted)
    print("Successful !!!. Save in ", output_file)
# ECB-MODE
def encrypt_file_ecb(in_file,out_file,password):
    passwordSalt=b')\x0b\xeb:\xa9\xf7\xb0\xeb!\xc6hg^W\x07\xca'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    # plaintext=open(filename,encoding='utf8').read()
    # plus= 16 - len(plaintext)%16
    # plaintext += " "*plus
    bs= AES.block_size
    finished= False
    cipher =AES.new(key,AES.MODE_ECB)
    while not finished:
        chunk = in_file.read(1024*bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))
    print("Successfull!!!")           
    
def decrypt_file_ecb(in_file,out_file,password):
    passwordSalt=b')\x0b\xeb:\xa9\xf7\xb0\xeb!\xc6hg^W\x07\xca'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)    
    bs = AES.block_size
    cipher = AES.new(key, AES.MODE_ECB)
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

# CBC-MODE
def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size #16 bytes
    salt = urandom(bs) #return a string of random bytes
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt)
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
    bs = AES.block_size
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
    bs = AES.block_size #16 bytes
    salt = urandom(bs) #return a string of random bytes
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    out_file.write(salt)
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
    bs = AES.block_size
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
    bs = AES.block_size #16 bytes
    salt = urandom(bs) #return a string of random bytes
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    out_file.write(salt)
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
    bs = AES.block_size
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
print("---ENCRYPT/DECRYPT WITH AES---")
print("Choose your option:\n")
print("1. Encrypt Text\n")
print("2. Decrypt Text\n")
print("3. Encrypt File\n")
print("4. Decrypt File\n")
option=input("Your option: ")
if option == '1':
    print("Choose your mode encrypt:\n")
    print("1. Encrypt ECB mode\n")
    print("2. Encrypt CBC mode\n")
    print("3. Encrypt CFB mode\n")
    print("4. Encrypt OFB mode\n")
    print("5. Encrypt CTR mode\n")
    opt=input("Your selection: ")
    if opt == '1':
        print('--ECB Mode--')
        val=input("Message: ")
        password=input("Secret key: ")
        plaintext=val
        key = hashlib.sha256(password.encode()).digest()
        plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)
        print ("Input data (CMS): "+binascii.hexlify(plaintext.encode()).decode())
        ciphertext = encrypt_ecb(plaintext.encode(),key,AES.MODE_ECB)
        print(ciphertext)
        print ("Cipher (ECB): "+binascii.hexlify(bytearray(ciphertext)).decode())
       
    if opt == '2':
        print('--CBC Mode--')
        val=input("Message: ")
        password=input("Secret key: ")
        ival=int(input("Initialization Vector:"))
        plaintext=val
        iv= hex(ival)[2:8].zfill(16)
        key = hashlib.sha256(password.encode()).digest()
        plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)
        print ("Input data (CMS): "+binascii.hexlify(plaintext.encode()).decode())
        ciphertext = encrypt_2(plaintext.encode(),key,AES.MODE_CBC,iv.encode())
        print ("Cipher (CBC): "+binascii.hexlify(bytearray(ciphertext)).decode())

    if opt == '3':
        print('--CFB Mode--')
        val=input("Message: ")
        password=input("Secret key: ")
        ival=int(input("Initialization Vector:"))
        plaintext=val
        iv= hex(ival)[2:8].zfill(16)
        key = hashlib.sha256(password.encode()).digest()
        plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)
        print ("Input data (CMS): "+binascii.hexlify(plaintext.encode()).decode())
        ciphertext = encrypt_2(plaintext.encode(),key,AES.MODE_CFB,iv.encode())
        print ("Cipher (CFB): "+binascii.hexlify(bytearray(ciphertext)).decode())

    if opt == '4':
        print('--OFB Mode--')
        val=input("Message: ")
        password=input("Secret key: ")
        ival=int(input("Initialization Vector:"))
        plaintext=val
        iv= hex(ival)[2:8].zfill(16)
        key = hashlib.sha256(password.encode()).digest()
        plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)
        print ("Input data (CMS): "+binascii.hexlify(plaintext.encode()).decode())
        ciphertext = encrypt_2(plaintext.encode(),key,AES.MODE_OFB,iv.encode())
        print ("Cipher (OFB): "+binascii.hexlify(bytearray(ciphertext)).decode())

    if opt == '5':
        print('--CTR Mode--')
        plaintext=input("Message: ")
        password=input("Password: ")
        encrypt_ctr_aes256(plaintext,password)
        
if option == '2':
    print("Choose your mode decrypt:\n")
    print("1. Decrypt ECB mode\n")
    print("2. Decrypt CBC mode\n")
    print("3. Decrypt CFB mode\n")
    print("4. Decrypt OFB mode\n")
    print("5. Decrypt CTR mode\n")
    opt=input("Your selection: ")
    if opt == '1':
        print('--ECB Mode--')
        ciphertext_ecb=input("Cipher: ")
        ciphertext=bytes.fromhex(ciphertext_ecb)
        password=input("Secret key: ")
        key = hashlib.sha256(password.encode()).digest()
        plaintext = decrypt_ecb(ciphertext,key,AES.MODE_ECB)
        plaintext_ = Padding.removePadding(plaintext.decode(),mode=0)
        print ("  decrypt: "+plaintext_)
    if opt == '2':
        print('--CBC Mode--')
        ciphertext_ecb=input("Cipher: ")
        ciphertext=bytes.fromhex(ciphertext_ecb)
        password=input("Secret key: ")
        ival=int(input("IV: "))
        iv= hex(ival)[2:8].zfill(16)
        key = hashlib.sha256(password.encode()).digest()
        plaintext = decrypt_2(ciphertext,key,AES.MODE_CBC,iv.encode())
        plaintext_ = Padding.removePadding(plaintext.decode(),mode=0)
        print ("  decrypt: "+plaintext_)
    if opt == '3':
        print('--CFB Mode--')
        ciphertext_ecb=input("Cipher: ")
        ciphertext=bytes.fromhex(ciphertext_ecb)
        password=input("Secret key: ")
        ival=int(input("IV: "))
        iv= hex(ival)[2:8].zfill(16)
        key = hashlib.sha256(password.encode()).digest()
        plaintext = decrypt_2(ciphertext,key,AES.MODE_CFB,iv.encode())
        plaintext_ = Padding.removePadding(plaintext.decode(),mode=0)
        print ("  decrypt: "+plaintext_)
    if opt == '4':
        print('--OFB Mode--')
        ciphertext_ecb=input("Cipher: ")
        ciphertext=bytes.fromhex(ciphertext_ecb)
        password=input("Secret key: ")
        ival=int(input("IV: "))
        iv= hex(ival)[2:8].zfill(16)
        key = hashlib.sha256(password.encode()).digest()
        plaintext = decrypt_2(ciphertext,key,AES.MODE_CFB,iv.encode())
        plaintext_ = Padding.removePadding(plaintext.decode(),mode=0)
    if opt == '5':
        print('--CTR Mode--')
        cipher=input("Your massage:")
        password=input("Your password:")
        iv=int(input("IV: "))
        decrypt_ctr_aes256(cipher,password,iv)
if option == '3':
    print("Choose your mode encrypt:\n")
    print("1. Encrypt ECB mode\n")
    print("2. Encrypt CBC mode\n")
    print("3. Encrypt CFB mode\n")
    print("4. Encrypt OFB mode\n")
    print("5. Encrypt CTR mode\n")
    opt=input("Your selection: ")
    if opt=='1':
        name1=input("Your file you want to encrypt:\n")
        name2=input("Your encrypted file:\n")
        password=input("Your secret key:\n")
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt_file_ecb(in_file, out_file, password)
    if opt== '2':
        name1=input("Your file you want to encrypt:\n")
        name2=input("Your encrypted file:\n")
        password=input("Your secret key:\n")
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt(in_file, out_file, password)
    if opt== '3':
        name1=input("Your file you want to encrypt:\n")
        name2=input("Your encrypted file:\n")
        password=input("Your secret key:\n")
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt_file_cfb(in_file, out_file, password)
    if opt== '4':
        name1=input("Your file you want to encrypt:\n")
        name2=input("Your encrypted file:\n")
        password=input("Your secret key:\n")
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         encrypt_file_ofb(in_file, out_file, password)
    elif opt=='5':
        filename=input("Your file:")
        password=input("Your key:")
        encrypt_file_ctr(filename,password)
elif option == '4':
    print("Choose your mode decrypt:\n")
    print("1. Decrypt ECB mode\n")
    print("2. Decrypt CBC mode\n")
    print("3. Decrypt CFB mode\n")
    print("4. Decrypt OFB mode\n")
    print("5. Decrypt CTR mode\n")
    opt=input("Your selection: ")
    if opt=='1':
        name1=input("Your file you want to decrypt:\n")
        name2=input("Your decrypted file:\n")
        password=input("Your secret key:\n")
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt(in_file, out_file, password)      
    elif opt=='2':
        name1=input("Your file you want to decrypt:\n")
        name2=input("Your decrypted file:\n")
        password=input("Your secret key:\n")
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt(in_file, out_file, password)
    elif opt=='3':
        name1=input("Your file you want to decrypt:\n")
        name2=input("Your decrypted file:\n")
        password=input("Your secret key:\n")
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt_file_cfb(in_file, out_file, password)
    elif opt=='4':
        name1=input("Your file you want to decrypt:\n")
        name2=input("Your decrypted file:\n")
        password=input("Your secret key:\n")       
        with open(name1, 'rb') as in_file, open(name2, 'wb') as out_file:
         decrypt_file_ofb(in_file, out_file, password)
    elif opt=='5':
        filename=input('Your file:')
        password=input('Your password:')
        iv=int(input('Your IV:'))
        decrypt_file_ctr(filename,password,iv)

        




