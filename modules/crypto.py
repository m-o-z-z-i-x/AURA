# ---------------------------------------------------------------------------- #
# DESCRIPTION: crypto primitives for MS-CHAPv2, MPPE, IKE Diffie-Hellman and CBC ciphers
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import hashlib
import hmac

from dataclasses import dataclass
from secrets import randbelow

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Hash import MD4
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
MAGIC_SERVER = b"Magic server to client signing constant"
MAGIC_PAD = b"Pad to make it do more than one iteration"
MAGIC_MASTER = b"This is the MPPE Master Key"
MAGIC_CLIENT_SEND = b"On the client side, this is the send key. on the server side, it is the receive key."
MAGIC_CLIENT_RECEIVE = b"On the client side, this is the receive key. on the server side, it is the send key."
SHS_PAD1 = bytes(40)
SHS_PAD2 = bytes([0xf2]) * 40
SALT_40 = bytes([0xd1, 0x26, 0x9e])

# group primes are copied from RFC 2409 section 6.2 and RFC 3526 sections 2 and 3
PRIME_2 = int(
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
  16
)
PRIME_5 = int(
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
  "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
  16
)
PRIME_14 = int(
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
  "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
  16
)

CIPHERS = {
  "aes128": (16, 16),
  "aes256": (32, 16),
  "3des": (24, 8)
}

@dataclass
class DhGroup:
  id: int
  prime: int
  generator: int
  size: int

DH_GROUPS = {
  2: DhGroup(2, PRIME_2, 2, 128),
  5: DhGroup(5, PRIME_5, 2, 192),
  14: DhGroup(14, PRIME_14, 2, 256)
}

def _md4(data):
  return MD4.new(data).digest()

def sha1(data):
  return hashlib.sha1(data).digest()

def _ntPasswordHash(password):
  return _md4(password.encode("utf-16-le"))

def _challengeHash(peerChallenge, authChallenge, username):
  return sha1(peerChallenge + authChallenge + username.encode("utf-8"))[:8]

def _desKey(key7):
  # spread 56 bits over 8 bytes and set odd parity in the low bit of each
  bits = int.from_bytes(key7, "big")
  spread = [(bits >> (49 - 7 * i)) & 0x7f for i in range(8)]
  return bytes((b << 1) | (bin(b).count("1") % 2 == 0) for b in spread)

def ntResponse(authChallenge, peerChallenge, username, password):
  challenge = _challengeHash(peerChallenge, authChallenge, username)
  padded = _ntPasswordHash(password).ljust(21, bytes(1))

  return b"".join(DES.new(_desKey(padded[i:i + 7]), DES.MODE_ECB).encrypt(challenge) for i in range(0, 21, 7))

def authenticatorResponse(password, ntResp, peerChallenge, authChallenge, username):
  digest = sha1(_md4(_ntPasswordHash(password)) + ntResp + MAGIC_SERVER)
  final = sha1(digest + _challengeHash(peerChallenge, authChallenge, username) + MAGIC_PAD)

  return "S=" + final.hex().upper()

def _newKeyFromSha(startKey, length):
  # rfc 3079 GetNewKeyFromSHA with the session key equal to the start key
  return sha1(startKey[:length] + SHS_PAD1 + startKey[:length] + SHS_PAD2)[:length]

def mppeStartKeys(password, ntResp, keyLength):
  # rfc 3079 start keys, which every rfc 3078 key change restarts from
  master = sha1(_md4(_ntPasswordHash(password)) + ntResp + MAGIC_MASTER)[:16]

  return tuple(sha1(master + SHS_PAD1 + magic + SHS_PAD2)[:keyLength] for magic in (MAGIC_CLIENT_SEND, MAGIC_CLIENT_RECEIVE))

def mppeKeys(password, ntResp, keyLength, bits = None):
  # allowed pairs: keyLength 8 with bits 40 (default) or 56, keyLength 16 with bits 128 (default)
  bits = bits or {8: 40, 16: 128}.get(keyLength)

  if (keyLength, bits) not in ((8, 40), (8, 56), (16, 128)):
    raise ValueError("mppe key needs keyLength 8 with bits 40 or 56, or keyLength 16 with bits 128")

  sendKey, receiveKey = (_newKeyFromSha(startKey, keyLength) for startKey in mppeStartKeys(password, ntResp, keyLength))

  # 40 and 56 bit keys keep 8 bytes but only part of them carries entropy
  if bits == 40:
    return SALT_40 + sendKey[3:], SALT_40 + receiveKey[3:]

  if bits == 56:
    return SALT_40[:1] + sendKey[1:], SALT_40[:1] + receiveKey[1:]

  return sendKey, receiveKey

class MppeStream:
  # the rc4 state continues across calls. per-packet rekeying means building a new MppeStream
  def __init__(self, key):
    self.cipher = ARC4.new(key)

  def encrypt(self, data):
    return self.cipher.encrypt(data)

  def decrypt(self, data):
    return self.cipher.decrypt(data)

def dhGenerate(group):
  private = 2 + randbelow(group.prime - 4)

  return private, pow(group.generator, private, group.prime).to_bytes(group.size, "big")

def dhShared(group, private, peerPublic):
  peer = int.from_bytes(peerPublic, "big")

  if not 1 < peer < group.prime - 1:
    raise ValueError("invalid diffie-hellman public value")

  return pow(peer, private, group.prime).to_bytes(group.size, "big")

def prf(hashName, key, data):
  if hashName not in ("sha1", "sha256"):
    raise ValueError("unsupported hash")

  return hmac.new(key, data, getattr(hashlib, hashName)).digest()

def _newCbc(cipher, key, iv, data):
  if cipher not in CIPHERS:
    raise ValueError("unsupported cipher")

  keySize, blockSize = CIPHERS[cipher]

  if len(key) != keySize or len(iv) != blockSize or len(data) % blockSize:
    raise ValueError("invalid key, iv or data length")

  return (DES3 if cipher == "3des" else AES).new(key, AES.MODE_CBC, iv)

def cbcEncrypt(cipher, key, iv, data):
  return _newCbc(cipher, key, iv, data).encrypt(data)

def cbcDecrypt(cipher, key, iv, data):
  return _newCbc(cipher, key, iv, data).decrypt(data)
# ---------------------------------------------------------------------------- #