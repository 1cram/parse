use der_parser::ber::*;
use der_parser::der::*;
use num_bigint::BigUint;
use secp256k1::{ecdsa, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

/// Path to the PKCS#7 signature file
const P7S_FILE_PATH: &str = "/home/marco/examples/rust/parse/src/test/signed_only_mex.p7s";
/// Path to the public key PEM file for verification
const PEM_FILE_PATH: &str = "/home/marco/examples/rust/parse/src/test/public_key.pem";
/// secp256k1 curve order in hexadecimal
const SECP256K1_ORDER: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Custom error types for PKCS#7 processing
#[derive(Debug)]
enum Pkcs7Error {
    IoError(std::io::Error),
    Base64Error(base64::DecodeError),
    Secp256k1Error(secp256k1::Error),
}

impl std::error::Error for Pkcs7Error {}

impl std::fmt::Display for Pkcs7Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pkcs7Error::IoError(e) => write!(f, "IO error: {}", e),
            Pkcs7Error::Base64Error(e) => write!(f, "Base64 decode error: {}", e),
            Pkcs7Error::Secp256k1Error(e) => write!(f, "Secp256k1 error: {}", e),
        }
    }
}

// Error conversion implementations
impl From<std::io::Error> for Pkcs7Error {
    fn from(error: std::io::Error) -> Self {
        Pkcs7Error::IoError(error)
    }
}

impl From<base64::DecodeError> for Pkcs7Error {
    fn from(error: base64::DecodeError) -> Self {
        Pkcs7Error::Base64Error(error)
    }
}

impl From<secp256k1::Error> for Pkcs7Error {
    fn from(error: secp256k1::Error) -> Self {
        Pkcs7Error::Secp256k1Error(error)
    }
}

/// Structure holding the extracted content from PKCS#7
struct SignedContent {
    /// Original message that was signed
    message: Vec<u8>,
    /// Digital signature in DER format
    signature: Vec<u8>,
    /// Public key extracted from the certificate
    public_key: Vec<u8>,
}

/// Extracts the original message from ContentInfo structure
fn extract_message(content_info: &BerObject) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Extracting message from ContentInfo...");
    if let BerObjectContent::Sequence(content_info_seq) = &content_info.content {
        for item in content_info_seq {
            if item.tag().0 == 0 && item.class() == Class::ContextSpecific {
                if let Ok(data) = item.as_slice() {
                    if let Ok((_, parsed)) = parse_der(data) {
                        if let BerObjectContent::OctetString(message) = parsed.content {
                            println!("✓ Message successfully extracted");
                            return Ok(message.to_vec());
                        }
                    }
                }
            }
        }
    }
    println!("✗ Failed to extract message");
    Err("Failed to extract message".into())
}

/// Extracts the public key from the certificate container
fn extract_certificate_and_key(signed_data_content: &[BerObject]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(cert_container) = signed_data_content.get(3) {
        if cert_container.tag() == Tag(0) && cert_container.class() == Class::ContextSpecific {
            println!("✓ Certificate container found");
            if let Ok(cert_data) = cert_container.as_slice() {
                if let Ok((_, cert_seq)) = parse_der(cert_data) {
                    if let BerObjectContent::Sequence(certs) = cert_seq.content {
                        println!("Found {} certificates", certs.len());
                        extract_public_key_from_cert(&certs[0])
                    } else {
                        Err("Invalid certificate sequence".into())
                    }
                } else {
                    Err("Failed to parse certificate data".into())
                }
            } else {
                Err("Failed to get certificate data".into())
            }
        } else {
            Err("Certificate container not found".into())
        }
    } else {
        Err("No certificate container at index 3".into())
    }
}

/// Extracts the digital signature from SignerInfo structure
fn extract_signature_from_signer_info(signer_info: &BerObject) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let BerObjectContent::Sequence(signer_info_seq) = &signer_info.content {
        println!("SignerInfo contains {} elements", signer_info_seq.len());

        // Debug information for SignerInfo elements
        for (i, element) in signer_info_seq.iter().enumerate() {
            println!(
                "Element {}: Tag={:?}, Class={:?}",
                i,
                element.tag(),
                element.class()
            );
            match &element.content {
                BerObjectContent::OctetString(data) => {
                    println!("  OctetString length: {} bytes", data.len());
                    println!(
                        "  First bytes: {:02x?}",
                        &data[..std::cmp::min(data.len(), 8)]
                    );
                }
                BerObjectContent::Integer(data) => {
                    println!("  Integer value: {:02x?}", data);
                }
                _ => println!("  Content type: {:?}", element.content),
            }
        }

        if let Some(signature_element) = signer_info_seq.last() {
            if let BerObjectContent::OctetString(signature) = &signature_element.content {
                println!("\n✓ Signature extracted:");
                println!("Length: {} bytes", signature.len());
                println!("Raw hex: {}", hex::encode(signature));

                if signature.starts_with(&[0x30]) {
                    println!("DER format signature detected");
                    if let Ok((_, parsed_sig)) = parse_der(signature) {
                        if let BerObjectContent::Sequence(sig_components) = parsed_sig.content {
                            println!("Signature contains {} components", sig_components.len());
                            for (i, comp) in sig_components.iter().enumerate() {
                                if let BerObjectContent::Integer(value) = &comp.content {
                                    println!("Component {}: {}", i, hex::encode(value.as_ref()));
                                }
                            }
                        }
                    }
                }
                return Ok(signature.to_vec());
            }
        }
    }
    Err("Failed to extract signature".into())
}

/// Normalizes the signature components according to secp256k1 requirements
fn normalize_signature_components(signature: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    let (_, sig_sequence) = parse_der(signature)?;
    if let BerObjectContent::Sequence(components) = sig_sequence.content {
        println!("Analyzing signature components...");

        // Extract r and s components
        let r = if let BerObjectContent::Integer(r_val) = &components[0].content {
            r_val.as_ref().to_vec()
        } else {
            return Err("Invalid r component".into());
        };

        let s = if let BerObjectContent::Integer(s_val) = &components[1].content {
            s_val.as_ref().to_vec()
        } else {
            return Err("Invalid s component".into());
        };

        println!("\nOriginal components:");
        println!("r: {}", hex::encode(&r));
        println!("s: {}", hex::encode(&s));

        // Convert to BigUint for mathematical operations
        let r_bigint = BigUint::from_bytes_be(&r);
        let s_bigint = BigUint::from_bytes_be(&s);
        let n = BigUint::parse_bytes(SECP256K1_ORDER.as_bytes(), 16)
            .ok_or("Failed to parse curve order")?;

        // Check if s needs to be normalized
        let half_n = &n >> 1;
        let s_low = if s_bigint > half_n {
            println!("✓ Normalizing s (s > n/2)");
            &n - &s_bigint
        } else {
            println!("✓ s is already normalized (s <= n/2)");
            s_bigint.clone()
        };

        let r_bytes = r_bigint.to_bytes_be();
        let s_low_bytes = s_low.to_bytes_be();

        println!("\nNormalized components:");
        println!("r: {}", hex::encode(&r_bytes));
        println!("s: {}", hex::encode(&s_low_bytes));

        // Create compact signature format
        let mut compact_low = [0u8; 64];
        let r_start = 32 - std::cmp::min(32, r_bytes.len());
        compact_low[r_start..32].copy_from_slice(&r_bytes[r_bytes.len().saturating_sub(32)..]);

        let s_start = 64 - std::cmp::min(32, s_low_bytes.len());
        compact_low[s_start..].copy_from_slice(&s_low_bytes[s_low_bytes.len().saturating_sub(32)..]);

        println!("\nCompact signature:");
        println!("{}", hex::encode(&compact_low));

        Ok(compact_low)
    } else {
        Err("Invalid signature sequence".into())
    }
}

/// Processes the PKCS#7 data and extracts all necessary components
fn process_pkcs7(pkcs7_data: &[u8]) -> Result<SignedContent, Box<dyn std::error::Error>> {
    let (_, pkcs7) = parse_der(pkcs7_data)?;

    if let BerObjectContent::Sequence(content) = &pkcs7.content {
        if content.len() > 1 {
            if let Ok(signed_data) = content[1].as_slice() {
                if let Ok((_, signed_data)) = parse_der(signed_data) {
                    if let BerObjectContent::Sequence(signed_data_content) = signed_data.content {
                        let message = extract_message(&signed_data_content[2])?;
                        let public_key = extract_certificate_and_key(&signed_data_content)?;

                        if let BerObjectContent::Set(signer_info_set) = &signed_data_content[4].content {
                            if !signer_info_set.is_empty() {
                                let signature = extract_signature_from_signer_info(&signer_info_set[0])?;

                                return Ok(SignedContent {
                                    message,
                                    signature,
                                    public_key,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Err("Failed to process PKCS#7 data".into())
}

/// Extracts the public key from a certificate
fn extract_public_key_from_cert(cert: &BerObject) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("\nAnalyzing certificate structure for public key extraction:");
    print_asn1_structure(cert, 0);

    if let BerObjectContent::Sequence(cert_seq) = &cert.content {
        for element in cert_seq {
            if let BerObjectContent::Sequence(seq) = &element.content {
                if seq.len() == 2 {
                    if let BerObjectContent::Sequence(alg_seq) = &seq[0].content {
                        // Check for ECDSA public key
                        if alg_seq.len() == 2 {
                            if let (BerObjectContent::OID(alg_oid), _) = (&alg_seq[0].content, &alg_seq[1].content) {
                                if alg_oid.to_string() == "1.2.840.10045.2.1" {  // ECDSA OID
                                    if let BerObjectContent::BitString(_, bit_string) = &seq[1].content {
                                        println!("✓ Public key found:");
                                        println!("  Length: {} bytes", bit_string.data.len());
                                        return Ok(bit_string.data.to_vec());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err("Failed to extract public key from certificate".into())
}

/// Prints ASN.1 structure in a hierarchical format
fn print_asn1_structure(obj: &BerObject, indent: usize) {
    let indent_str = " ".repeat(indent);
    println!(
        "{}Tag: {:?}, Class: {:?}",
        indent_str,
        obj.tag(),
        obj.class()
    );
    match &obj.content {
        BerObjectContent::Sequence(seq) => {
            println!("{}Sequence with {} elements", indent_str, seq.len());
            for (i, item) in seq.iter().enumerate() {
                println!("{}Element {}:", indent_str, i);
                print_asn1_structure(item, indent + 2);
            }
        }
        BerObjectContent::Set(set) => {
            println!("{}Set with {} elements", indent_str, set.len());
            for (i, item) in set.iter().enumerate() {
                println!("{}Element {}:", indent_str, i);
                print_asn1_structure(item, indent + 2);
            }
        }
        BerObjectContent::OID(oid) => {
            println!("{}OID: {}", indent_str, oid);
        }
        BerObjectContent::OctetString(data) => {
            println!("{}OctetString: {} bytes", indent_str, data.len());
        }
        _ => println!("{}Other content type: {:?}", indent_str, obj.content),
    }
}

/// Prints a formatted section header
fn print_section_header(title: &str) {
    println!("\n{}", "=".repeat(80));
    println!("  {}", title);
    println!("{}", "=".repeat(80));
}

/// Main function that coordinates the PKCS#7 signature verification process
fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_section_header("PKCS#7 SIGNATURE VERIFICATION START");
    println!("Input file: {}", P7S_FILE_PATH);

    // Load and parse PKCS#7 file
    let pkcs7_data = fs::read(P7S_FILE_PATH)?;
    println!("PKCS#7 file loaded, size: {} bytes", pkcs7_data.len());

    let content = process_pkcs7(&pkcs7_data)?;

    // Original message information
    print_section_header("ORIGINAL MESSAGE");
    println!("Content: {:?}", String::from_utf8_lossy(&content.message));
    println!("Length: {} bytes", content.message.len());

    // Message hash calculation
    print_section_header("MESSAGE HASH");
    let mut hasher = Sha256::new();
    hasher.update(&content.message);
    let message_hash = hasher.finalize();
    let message_hash_array: [u8; 32] = message_hash.try_into()?;
    println!("SHA-256: {}", hex::encode(&message_hash_array));
    println!("Length: {} bytes", message_hash_array.len());

    // Digital signature information
    print_section_header("DIGITAL SIGNATURE");
    println!("DER encoded signature:");
    println!("Raw hex: {}", hex::encode(&content.signature));
    println!("Length: {} bytes", content.signature.len());

    // Public key information
    print_section_header("PUBLIC KEY");
    println!("From PKCS#7:");
    println!("Hex: {}", hex::encode(&content.public_key));
    println!("Length: {} bytes", content.public_key.len());

    // Signature normalization
    print_section_header("SIGNATURE NORMALIZATION");
    let compact_signature = normalize_signature_components(&content.signature)?;

    // Secp256k1 signature verification
    print_section_header("SECP256K1 VERIFICATION");
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_slice(&content.public_key)?;
    let message = Message::from_digest(message_hash_array);
    let signature = ecdsa::Signature::from_compact(&compact_signature)?;

    // Public key comparison
    print_section_header("PUBLIC KEY COMPARISON");
    println!("Reading public key from PEM file...");
    let pem_key = fs::read_to_string(PEM_FILE_PATH)?;
    let pem_base64 = pem_key
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let pem_bytes = base64::decode(&pem_base64)?;
    let (_, spki) = parse_der(&pem_bytes)?;

    let key_bytes = if let BerObjectContent::Sequence(spki_seq) = &spki.content {
        if spki_seq.len() == 2 {
            if let BerObjectContent::BitString(_, bit_string) = &spki_seq[1].content {
                bit_string.data.to_vec()
            } else {
                return Err("Invalid public key format".into());
            }
        } else {
            return Err("Invalid SPKI format".into());
        }
    } else {
        return Err("Invalid SPKI content".into());
    };

    println!("From PEM file:");
    println!("Hex: {}", hex::encode(&key_bytes));
    println!("Length: {} bytes", key_bytes.len());
    println!("\nKeys match: {}", content.public_key == key_bytes);

    // Verification results
    print_section_header("VERIFICATION RESULTS");
    println!("Secp256k1 verification:");
    match secp.verify_ecdsa(&message, &signature, &pubkey) {
        Ok(_) => println!("✓ Valid signature"),
        Err(e) => println!("✗ Verification error: {:?}", e),
    }

    println!("\nOpenSSL verification:");
    let mut msg_file = NamedTempFile::new()?;
    let mut sig_file = NamedTempFile::new()?;

    msg_file.write_all(&content.message)?;
    sig_file.write_all(&content.signature)?;

    let verify_output = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            PEM_FILE_PATH,
            "-signature",
            sig_file.path().to_str().unwrap(),
            msg_file.path().to_str().unwrap(),
        ])
        .output()?;

    match String::from_utf8_lossy(&verify_output.stdout).trim() {
        "Verified OK" => println!("✓ Valid signature"),
        _ => println!("✗ Verification failed"),
    }

    print_section_header("VERIFICATION COMPLETE");
    Ok(())
}