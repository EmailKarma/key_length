import subprocess
import dns.resolver
import re
import base64
import tempfile
import os

def get_dkim_record(selector: str, domain: str) -> str:
    """Retrieve the DKIM DNS TXT record for a given selector and domain."""
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for txt_record in answers:
            # Decode each part to a string, then join and strip leading and trailing quotes
            record = ''.join(part.decode('utf-8') for part in txt_record.strings).strip('"')
            return record
    except dns.resolver.NoAnswer:
        print("No DKIM record found.")
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist.")
    return None

def parse_dkim_key_length(dkim_record: str) -> tuple:
    """Extract the public key and determine its key length using OpenSSL."""
    # Extract the "p=" part, which contains the public key
    match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_record)
    if not match:
        print("Public key not found in DKIM record.")
        return None, None
    
    public_key_b64 = match.group(1)
    
    # Decode the base64-encoded public key
    try:
        public_key_der = base64.b64decode(public_key_b64)
    except Exception as e:
        print(f"Error decoding public key: {e}")
        return None, None
    
    # Wrap the key in PEM format
    public_key_pem = (
        "-----BEGIN PUBLIC KEY-----\n" +
        "\n".join(public_key_b64[i:i+64] for i in range(0, len(public_key_b64), 64)) +
        "\n-----END PUBLIC KEY-----\n"
    )
    
    # Write the PEM-formatted key to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(public_key_pem.encode())
        tmp_filename = tmp_file.name

    try:
        # Use OpenSSL to parse the key and determine its length
        with subprocess.Popen(
            ['openssl', 'rsa', '-pubin', '-text', '-noout', '-in', tmp_filename],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as proc:
            stdout, stderr = proc.communicate()
            if stderr:
                print("Error parsing the key:", stderr.decode())
                return public_key_pem, None
            
            # Parse key length from OpenSSL output
            match = re.search(r'Public-Key: \((\d+) bit\)', stdout.decode())
            if match:
                key_length = int(match.group(1))
                return public_key_pem, key_length
    finally:
        # Clean up the temporary file
        os.remove(tmp_filename)

    return public_key_pem, None

def main():
    selector = input("Enter the DKIM selector: ")
    domain = input("Enter the domain: ")
    
    # Retrieve the DKIM record
    dkim_record = get_dkim_record(selector, domain)
    if not dkim_record:
        print("Failed to retrieve DKIM record.")
        return
    
    # Determine key length and get the PEM-formatted public key
    public_key, key_length = parse_dkim_key_length(dkim_record)
    if key_length:
        print(f"DKIM Public Key:\n{public_key}")
        print(f"DKIM Public Key Length: {key_length} bits")
    else:
        print("Failed to determine the key length.")

if __name__ == "__main__":
    main()
