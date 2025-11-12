# quick_reset.py
from ecdsa import SigningKey, NIST384p
import json
import base64
import datetime
import uuid
import re

print("🔄 Resetting HVM Panel License System...")

# Generate new keys
private_key = SigningKey.generate(curve=NIST384p)
public_key = private_key.get_verifying_key()
public_hex = public_key.to_string().hex()

# Save private key
with open('private_key.pem', 'wb') as f:
    f.write(private_key.to_pem())

# Generate license for current machine
machine_id = hex(uuid.getnode())
expires = datetime.datetime.now() + datetime.timedelta(days=365)

license_data = {
    'machine_id': machine_id,
    'expires': expires.isoformat()
}

data_str = json.dumps(license_data)
data_bytes = data_str.encode('utf-8')
signature = private_key.sign(data_bytes)
combined = data_bytes + b'||' + signature
license_key = base64.b64encode(combined).decode('utf-8')

# Update hvm.py
with open('hvm.py', 'r') as f:
    content = f.read()

content = re.sub(r"PUBLIC_HEX = '[^']*'", f"PUBLIC_HEX = '{public_hex}'", content)

with open('hvm.py', 'w') as f:
    f.write(content)

print("✅ Reset complete!")
print(f"Machine ID: {machine_id}")
print("\nYour new license key:")
print("=" * 50)
print(license_key)
print("=" * 50)
print("\nRestart HVM Panel and use this license key.")
