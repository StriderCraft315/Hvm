# license_maker.py
import json
import base64
import datetime
from ecdsa import SigningKey, NIST384p
import uuid
import sys
import os
import re

def load_private_key():
    """Load the existing private key from private_key.pem"""
    try:
        with open('private_key.pem', 'rb') as f:
            private_key = SigningKey.from_pem(f.read())
        return private_key
    except FileNotFoundError:
        print("❌ private_key.pem not found in current directory!")
        print("Please make sure private_key.pem is in the same directory as this script.")
        return None
    except Exception as e:
        print(f"❌ Error loading private key: {e}")
        return None

def get_public_hex(private_key):
    """Extract public key hex from private key"""
    public_key = private_key.get_verifying_key()
    return public_key.to_string().hex()

def update_hvm_public_key(public_hex):
    """Update the PUBLIC_HEX variable in hvm.py"""
    try:
        with open('hvm.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find and replace the PUBLIC_HEX variable
        old_pattern = r"PUBLIC_HEX = '[^']*'"
        new_public = f"PUBLIC_HEX = '{public_hex}'"
        
        if re.search(old_pattern, content):
            content = re.sub(old_pattern, new_public, content)
            with open('hvm.py', 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ Updated PUBLIC_HEX in hvm.py")
            return True
        else:
            print("❌ Could not find PUBLIC_HEX variable in hvm.py")
            return False
            
    except Exception as e:
        print(f"❌ Error updating hvm.py: {e}")
        return False

def validate_license(license_key, public_hex):
    """Test license validation"""
    from ecdsa import VerifyingKey, BadSignatureError
    
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_hex), curve=NIST384p)
        decoded = base64.b64decode(license_key)
        data_b, sign = decoded.rsplit(b'||', 1)
        data = data_b.decode()
        vk.verify(sign, data_b)
        license_data = json.loads(data)
        
        print("✅ License validation successful!")
        print(f"   Machine ID: {license_data['machine_id']}")
        print(f"   Expires: {license_data['expires']}")
        return True, license_data
        
    except (BadSignatureError, ValueError, json.JSONDecodeError) as e:
        print(f"❌ License validation failed: {e}")
        return False, str(e)

def make_license(machine_id, days=365):
    """Generate a license key using the existing private key"""
    
    # Load the private key
    private_key = load_private_key()
    if not private_key:
        return None, None
    
    # Get public key
    public_hex = get_public_hex(private_key)
    print(f"✅ Loaded private key from private_key.pem")
    print(f"   Public key: {public_hex[:20]}...")
    
    # Create license data
    expires = datetime.datetime.now() + datetime.timedelta(days=days)
    license_data = {
        'machine_id': machine_id,
        'expires': expires.isoformat(),
        'issued': datetime.datetime.now().isoformat(),
        'days_valid': days
    }
    
    # Sign and encode
    data_str = json.dumps(license_data)
    data_bytes = data_str.encode('utf-8')
    signature = private_key.sign(data_bytes)
    combined = data_bytes + b'||' + signature
    license_key = base64.b64encode(combined).decode('utf-8')
    
    return license_key, public_hex

def main():
    print("🔑 HVM Panel License Maker")
    print("=" * 50)
    print("Using private_key.pem from current directory")
    print()
    
    # Check if private key exists
    if not os.path.exists('private_key.pem'):
        print("❌ private_key.pem not found!")
        print("Please make sure private_key.pem is in the same directory as this script.")
        return
    
    # Get machine ID
    machine_id = input("Enter machine ID (hex string, or 'auto' for current machine): ").strip()
    if machine_id.lower() == 'auto':
        machine_id = hex(uuid.getnode())
        print(f"   Using machine ID: {machine_id}")
    
    # Get validity period
    try:
        days = int(input("Enter number of days valid (default 365): ") or "365")
    except ValueError:
        days = 365
        print("   Using default: 365 days")
    
    print("\n" + "=" * 50)
    
    # Generate license
    license_key, public_hex = make_license(machine_id, days)
    
    if not license_key:
        print("❌ Failed to generate license")
        return
    
    print("\n✅ License generated successfully!")
    print("=" * 60)
    print("YOUR LICENSE KEY:")
    print("=" * 60)
    print(license_key)
    print("=" * 60)
    
    # Update hvm.py with correct public key
    print("\n🔄 Updating hvm.py with correct public key...")
    if update_hvm_public_key(public_hex):
        print("✅ hvm.py updated successfully!")
    else:
        print("❌ Failed to update hvm.py automatically")
        print("Please manually update the PUBLIC_HEX variable in hvm.py with:")
        print(f"PUBLIC_HEX = '{public_hex}'")
    
    # Test validation
    print("\n🧪 Testing license validation...")
    success, result = validate_license(license_key, public_hex)
    
    if success:
        print("\n🎉 Everything is ready!")
        print("\nNext steps:")
        print("1. Restart your HVM Panel: python hvm.py")
        print("2. Enter the license key above when prompted")
        print("3. Your panel should now activate successfully!")
    else:
        print("\n⚠️  License generated but validation failed!")
        print("This usually means the public key wasn't updated correctly.")
        print("Please manually update hvm.py with the public key shown above.")

def batch_make_licenses():
    """Generate multiple licenses for different machine IDs"""
    print("🔑 Batch License Generator")
    print("=" * 50)
    
    private_key = load_private_key()
    if not private_key:
        return
    
    public_hex = get_public_hex(private_key)
    
    machine_ids = []
    print("Enter machine IDs (one per line, empty line to finish):")
    while True:
        machine_id = input().strip()
        if not machine_id:
            break
        machine_ids.append(machine_id)
    
    if not machine_ids:
        print("No machine IDs entered.")
        return
    
    try:
        days = int(input("Enter days valid for all licenses (default 365): ") or "365")
    except ValueError:
        days = 365
    
    print("\n" + "=" * 50)
    print(f"Generating {len(machine_ids)} licenses...")
    
    licenses = {}
    for machine_id in machine_ids:
        license_key, _ = make_license(machine_id, days)
        if license_key:
            licenses[machine_id] = license_key
            print(f"✅ Generated license for {machine_id}")
    
    # Save to file
    if licenses:
        with open('licenses.txt', 'w') as f:
            for machine_id, license_key in licenses.items():
                f.write(f"{machine_id}: {license_key}\n")
        print(f"\n✅ Saved {len(licenses)} licenses to licenses.txt")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "batch":
        batch_make_licenses()
    else:
        main()
