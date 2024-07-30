import sys
import hmac
import hashlib
import re

def calculate_key(data, key):
    # Convert the hexadecimal key to bytes
    key_bytes = bytes.fromhex(key)
    data_bytes = bytes.fromhex(data)
    # Calculate HMAC-SHA1 in hexadecimal format
    return hmac.new(key_bytes, data_bytes, hashlib.sha1).hexdigest()

def main():
    if len(sys.argv) != 2:
        print("Usage: supermicro-ipmi-key <MAC>")
        sys.exit(1)

    mac = sys.argv[1]

    # Validate MAC address
    if re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
        mac = mac.replace(":", "")
        key = "8544E3B47ECA58F9583043F8"
        license_key = calculate_key(mac, key)[:24]
        for i in range(0, 24, 4):
            print(license_key[i:i+4], end=" ")
        print()
    else:
        print(f"Invalid MAC address: {mac}")

if __name__ == "__main__":
    main()
