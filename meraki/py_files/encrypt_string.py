from Crypto.Cipher import AES
import base64

BLOCK_SIZE = 16                                                                 # 16, 24, or 32 for AES

PADDING = '{'
# chunk += b' ' * (16 - (len(chunk) % 16))
pad = lambda e: e + (BLOCK_SIZE - (len(e) % BLOCK_SIZE)) * PADDING

EncodeAES = lambda p, e: base64.b64encode(p.encrypt(pad(e)))

DecodeAES = lambda p, e: p.decrypt(base64.b64decode(e)).decode("UTF-8").rstrip(PADDING)

secret = b'yourownkeycodewouldgohere'

print ("\nThe key: ", secret)
print("\n")

def enc(p, e):
    password = AES.new(p)
    pString = e
    encoded = EncodeAES(password, pString)
    encoded = encoded.decode('utf-8')
    return encoded

def dec(p, e):
    password = AES.new(p)
    enc = e
    enc = enc.encode('utf-8')
    decoded = DecodeAES(password, enc)
    return decoded


def run(e, p):
    pString = e
    key = p
    encoded = enc(key, pString)
    decoded = dec(key, encoded)
    return encoded, decoded


if __name__=="__main__":
    # pString = "This is for testing purposes"
    pString = input("Enter anything: ")
    encoded, decoded = run(pString, secret)
    print("\n")
    print("Encrypted : ", encoded)
    print("\n")
    print("Decrypted : ", decoded)

