
 # IETF-Voucher
 
 Voucher reference implementation as per [RFC 8366 - A Voucher Artifact for Bootstrapping Protocols](https://datatracker.ietf.org/doc/html/rfc8366) and 
 [RFC 8995 - Manufacturer Usage Description Specification](https://datatracker.ietf.org/doc/html/rfc8995)
 
 ## Usage

This module comes with the following components: 

- a `VoucherArtifact`, which is a simple structure containing all fields in relation to the reference document.
- a `VerifiedVoucher` which is a `VoucherArtifact` that passes ~all~ (most, at time of writing) checks included in the reference document, such as expiry time or the exclusivity of nonces and expiry dates.
- a `SignedVoucher`, which is a CMS wrapped and signed `VoucherArtifact` 
- a `VoucherRequestArtifact`, which is a structure holding all information relating to voucher requests
- a `SignedVoucherRequest`, which is a CMS wrapped and signed `VoucherRequestArtifact`
- a `AgentSignedData` struct which carries agent signed data

# Feature flags

- `openssl` enabled openssl support. Certificates are directly parsed into `openssl::x509::X509` structs and public keys into `openssl::pkey::Pkey<Public>` structs. You also need this feature for `CMSSignedVouchers` which are needed by some standards.
- `clock` enables use of `chrono::now`, only enable if your device supports real time clocks
- `json` enables `JSON-in-JWS` Vouchers which are needed in `BRSKI-PRM`. The `AgentSignedData` struct supports JWS signeage with a private key. This feature also automatically enables binary encoded Base64 JSON fields as defined in the standard.


# TODO
[ ] support RUSTLS instead of Openssl
[ ] support `no-std`
[ ] support `no-panic`