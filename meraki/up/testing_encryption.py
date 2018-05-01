import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

pathway = "meraki/up/"


def encrypt(key, filename, le):
    chunksize = 64*1024
    output_file = filename[-le:]
    # file_size = str(s).zfill(16)
    file_size = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor_object = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, "rb") as infile:
            with open(pathway + "enc_" + output_file, "wb") as outfile:
                    outfile.write(file_size.encode("utf-8"))
                    outfile.write(IV)

                    while True:
                            chunk = infile.read(chunksize)

                            if len(chunk) == 0:
                                    break                                           # run out of data
                            elif len(chunk) % 16 != 0:
                                    chunk += b' ' * (16 - (len(chunk) % 16))         # need to pad due to not having a 16 byte block

                            outfile.write(encryptor_object.encrypt(chunk))


def decrypt(key, filename, of, ofl, ef, efl):
    output_file = str(of)
    chunksize = (64*1024)
    with open(filename, "rb") as infile:
            file_size = int(infile.read(16))
            IV = infile.read(16)

            decryptor_object = AES.new(key, AES.MODE_CBC, IV)

            with open(pathway + "dec_" + output_file, "wb") as outfile:
                    while True:
                            chunk = infile.read(chunksize)
                            if len(chunk) == 0:
                                    break
                            outfile.write(decryptor_object.decrypt(chunk))
                    # Removes the padding we added if it was necessary
                    outfile.truncate(file_size)


def get_key(password):
        hashed = SHA256.new(password.encode('utf-8'))
        return hashed.digest()

