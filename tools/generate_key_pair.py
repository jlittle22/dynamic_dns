from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
private_key = Ed25519PrivateKey.generate()
signature = private_key.sign(b"my authenticated message")
public_key = private_key.public_key()
# Raises InvalidSignature if verification fails
public_key.verify(signature, b"my authenticated message")

print(f"public:  {public_key.public_bytes_raw()}")
print(f"private: {private_key.private_bytes_raw()}")

with open('public.key', 'wb') as f:
    f.write(public_key.public_bytes_raw())

with open('private.key', 'wb') as f:
    f.write(private_key.private_bytes_raw())
