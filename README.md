# DKIM Key Length Checker

Determine the length of a DKIM public key value using OpenSSL.

This CLI tool retrieves a DKIM DNS TXT record, extracts the `p=` public
key value, converts it to PEM format, and determines the RSA key length.

------------------------------------------------------------------------

## Features

-   DNS lookup of DKIM TXT records
-   Extracts `p=` public key
-   Converts key to PEM format
-   Uses OpenSSL to detect RSA key length
-   Outputs:
    -   PEM-formatted public key
    -   Key length (e.g., 1024b, 2048b)
-   Supports text and JSON output modes
-   Optional custom DNS resolver

------------------------------------------------------------------------

## Requirements

-   Python 3.8+
-   OpenSSL installed and available in your system PATH
-   Python package:
    -   `dnspython`

### Install Dependencies

``` bash
pip install -r requirements.txt
```

------------------------------------------------------------------------

## Usage

Basic usage (positional arguments):

``` bash
python3 key_length.py <selector> <domain>
```

Example:

``` bash
python3 key_length.py google example.com
```

------------------------------------------------------------------------

## Example Output (Text Mode)

    DKIM Public Key (PEM):
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqh...
    -----END PUBLIC KEY-----

    DKIM Public Key Length: 2048b

------------------------------------------------------------------------

## JSON Output Mode

``` bash
python3 key_length.py google example.com --output json
```

------------------------------------------------------------------------

## Security Notes

-   Temporary PEM files are deleted immediately after parsing.
-   No data is stored.
-   Read-only DNS lookups only.

------------------------------------------------------------------------

## License

MIT License
