# Changelog

All notable changes to this project are documented here.

------------------------------------------------------------------------

## \[0.2.0\] - CLI Redesign

### Changed

-   Replaced required flags with positional arguments:

        python3 key_length.py <selector> <domain>

### Added

-   `--output` flag with `text` and `json` modes
-   Automatic PEM public key output in text mode
-   Structured JSON output
-   Optional `--nameserver`
-   Optional `--timeout`
-   Optional `--openssl` path override

------------------------------------------------------------------------

## \[0.1.0\] - Initial Release

### Added

-   DNS retrieval of DKIM TXT records
-   Extraction of `p=` public key value
-   Base64 to PEM conversion
-   OpenSSL parsing of RSA key length
-   Temporary file handling for OpenSSL

------------------------------------------------------------------------

## Known Limitations

-   RSA keys only
-   Requires OpenSSL installed locally
