import hashlib
import ecdsa
import base58
import requests

# 1. Decimal private key daxil et
decimal_private_key = 1234567890  # Buraya decimal private key yaz!

# 2. Hex formatına çevir (64 simvol)
private_key_hex = hex(decimal_private_key)[2:].zfill(64)

# 3. Public key yarat
sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()
public_key_bytes = b'\x04' + vk.to_string()

# 4. Public key-dən Bitcoin ünvanı çıxar (Legacy P2PKH)
sha256 = hashlib.sha256(public_key_bytes).digest()
ripemd160 = hashlib.new('ripemd160', sha256).digest()
prefixed = b'\x00' + ripemd160
checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
address_bytes = prefixed + checksum
btc_address = base58.b58encode(address_bytes).decode()

print("Bitcoin Ünvanı:", btc_address)
print("Private key (hex):", private_key_hex)

# 5. Ünvan balansını yoxla (Blockchain API)
def get_balance(address):
    url = f"https://blockchain.info/rawaddr/{address}"
    r = requests.get(url)
    if r.status_code == 200:
        data = r.json()
        return data["final_balance"] / 1e8  # BTC olaraq
    return None

balance = get_balance(btc_address)
print("BTC balansı:", balance)
