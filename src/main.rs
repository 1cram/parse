use std::fs;
use der_parser::ber::*;
use der_parser::der::*;
use k256::EncodedPoint;
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

// Definizione dei percorsi dei file
const P7S_FILE_PATH: &str = "/home/marco/examples/rust/parse/src/try/signed_message_smime.p7s";
const PCA_PUBLIC_KEY_PATH: &str = "/home/marco/examples/rust/parse/src/try/public_key.der";



fn verify_pkcs7_signature(data: &[u8], pca_public_key: &[u8]) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
    println!("Starting PKCS#7 signature verification");
    let (_, pkcs7) = parse_der(data)?;

    if let BerObjectContent::Sequence(content) = &pkcs7.content {
        if content.len() > 1 {
            if let Ok(signed_data) = content[1].as_slice() {
                if let Ok((_, signed_data)) = parse_der(signed_data) {
                    if let BerObjectContent::Sequence(signed_data_content) = signed_data.content {
                        let message = extract_message(&signed_data_content[2])?;
                        println!("Extracted message: {:?}", String::from_utf8_lossy(&message));

                        let certificate = extract_certificate(&signed_data_content[3])?;
                        println!("Certificate extracted, length: {} bytes", certificate.len());

                        if let BerObjectContent::Set(signer_info_set) = &signed_data_content[4].content {
                            if !signer_info_set.is_empty() {
                                let signer_info = &signer_info_set[0];

                                let signature = extract_signature(signer_info)?;
                                println!("Extracted signature: {:?}", signature);

                                let authenticated_attributes = extract_authenticated_attributes(signer_info)?;
                                println!("Authenticated attributes extracted, length: {} bytes", authenticated_attributes.len());

                                let message_digest = extract_message_digest(&authenticated_attributes)?;
                                println!("Extracted message digest: {:?}", message_digest);

                                // Verify message digest
                                let calculated_message_digest = Sha256::digest(&message);
                                println!("Calculated message digest: {:?}", calculated_message_digest);
                                assert_eq!(message_digest, calculated_message_digest.as_slice(), "Message digest mismatch");

                                // Extract public key from certificate
                                let (_, cert) = X509Certificate::from_der(&certificate)?;
                                let public_key = cert.public_key();
                                let key_bytes = extract_public_key_bytes(&public_key.raw)?;
                                println!("Extracted public key: {:?}", key_bytes);

                                let encoded_point = EncodedPoint::from_bytes(&key_bytes)?;
                                let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)?;
                                println!("Created VerifyingKey");

                                // Try different formats for authenticated attributes
                                let auth_attr_formats = vec![
                                    authenticated_attributes.clone(),
                                    prepare_auth_attr_for_hash(&authenticated_attributes),
                                    [&[0x31], authenticated_attributes.as_slice()].concat(),
                                ];

                                for (i, auth_attr) in auth_attr_formats.iter().enumerate() {
                                    let auth_attr_hash = Sha256::digest(auth_attr);
                                    println!("Auth attr hash {}: {:?}", i, auth_attr_hash);

                                    // Parse the DER-encoded signature
                                    let (_, signature_sequence) = parse_der(&signature)?;
                                    if let BerObjectContent::Sequence(components) = signature_sequence.content {
                                        if components.len() == 2 {
                                            let r = components[0].as_bigint()?.to_bytes_be().1;
                                            let s = components[1].as_bigint()?.to_bytes_be().1;
                                            println!("Signature r: {:?}", r);
                                            println!("Signature s: {:?}", s);

                                            let r_bytes: [u8; 32] = r.try_into().map_err(|_| "Failed to convert r to [u8; 32]")?;
                                            let s_bytes: [u8; 32] = s.try_into().map_err(|_| "Failed to convert s to [u8; 32]")?;

                                            let signature1 = Signature::from_der(&signature)?;
                                            let signature2 = Signature::from_scalars(r_bytes, s_bytes)?;

                                            println!("Verifying with auth_attr_hash {}...", i);
                                            let result1 = verifying_key.verify(auth_attr_hash.as_slice(), &signature1);
                                            let result2 = verifying_key.verify(auth_attr_hash.as_slice(), &signature2);
                                            println!("Verification result (DER): {:?}", result1);
                                            println!("Verification result (from_scalars): {:?}", result2);

                                            if result1.is_ok() || result2.is_ok() {
                                                println!("Signature verified successfully with auth_attr_hash {}", i);

                                                // Verify certificate with PCA public key
                                                let pca_verifying_key = VerifyingKey::from_sec1_bytes(pca_public_key)?;
                                                let cert_signature = cert.signature_value.as_ref();
                                                let cert_tbs = cert.tbs_certificate.as_ref();
                                                let cert_verify_result = pca_verifying_key.verify(cert_tbs, &Signature::from_der(cert_signature)?);
                                                println!("Certificate verification result: {:?}", cert_verify_result);
                                                assert!(cert_verify_result.is_ok(), "Invalid certificate signature");

                                                let signer_name = cert.subject().to_string();
                                                println!("Signer name: {}", signer_name);

                                                return Ok((message, signer_name, "PCA Authority".to_string()));
                                            }
                                        }
                                    }
                                }

                                // If we get here, all verification attempts failed
                                return Err("Invalid signature: all verification attempts failed".into());
                            }
                        }
                    }
                }
            }
        }
    }

    Err("Invalid PKCS#7 structure".into())
}

fn extract_authenticated_attributes(
    signer_info: &BerObject,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Extracting authenticated attributes");
    if let BerObjectContent::Sequence(signer_info_seq) = &signer_info.content {
        for item in signer_info_seq {
            if item.tag() == Tag(0) && item.class() == Class::ContextSpecific {
                if let Ok(data) = item.as_slice() {
                    println!(
                        "Authenticated attributes found, length: {} bytes",
                        data.len()
                    );
                    // We need to prepend the DER encoding for a SET OF
                    let mut der_encoded = vec![0x31, 0x82]; // SET OF tag and indefinite length
                    der_encoded.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    der_encoded.extend_from_slice(data);
                    return Ok(der_encoded);
                }
            }
        }
    }
    println!("Failed to extract authenticated attributes");
    Err("Failed to extract authenticated attributes".into())
}

fn extract_message_digest(
    authenticated_attributes: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Extracting message digest from authenticated attributes");
    println!(
        "Authenticated attributes (first 50 bytes): {:?}",
        &authenticated_attributes[..50.min(authenticated_attributes.len())]
    );

    let (_, parsed) = parse_der(authenticated_attributes)?;
    print_asn1_structure(&parsed, 0);

    if let BerObjectContent::Set(attr_set) = parsed.content {
        for attr in attr_set {
            if let BerObjectContent::Sequence(attr_content) = &attr.content {
                if attr_content.len() == 2 {
                    if let BerObjectContent::OID(oid) = &attr_content[0].content {
                        println!("Found OID: {}", oid);
                        if oid.to_string() == "1.2.840.113549.1.9.4" {
                            if let BerObjectContent::Set(digest_set) = &attr_content[1].content {
                                if let BerObjectContent::OctetString(digest) =
                                    &digest_set[0].content
                                {
                                    println!("Message digest found in authenticated attributes");
                                    return Ok(digest.to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("Failed to extract message digest from authenticated attributes");
    Err("Failed to extract message digest".into())
}

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

fn extract_message(content_info: &BerObject) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Extracting message from ContentInfo");
    if let BerObjectContent::Sequence(content_info_seq) = &content_info.content {
        for item in content_info_seq {
            if item.tag().0 == 0 && item.class() == Class::ContextSpecific {
                if let Ok(data) = item.as_slice() {
                    if let Ok((_, parsed)) = parse_der(data) {
                        if let BerObjectContent::OctetString(message) = parsed.content {
                            println!("Message successfully extracted");
                            return Ok(message.to_vec());
                        }
                    }
                }
            }
        }
    }
    println!("Failed to extract message from ContentInfo");
    Err("Failed to extract message".into())
}

fn extract_certificate(cert_content: &BerObject) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Extracting certificate");
    if let Ok(data) = cert_content.as_slice() {
        println!("Certificate successfully extracted");
        Ok(data.to_vec())
    } else {
        println!("Failed to extract certificate");
        Err("Failed to extract certificate".into())
    }
}

fn extract_signature(signer_info: &BerObject) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Extracting signature from SignerInfo");
    if let BerObjectContent::Sequence(signer_info_seq) = &signer_info.content {
        println!(
            "SignerInfo is a Sequence with {} elements",
            signer_info_seq.len()
        );
        if let Some(signature_element) = signer_info_seq.last() {
            println!(
                "Examining last element with tag {:?}",
                signature_element.tag()
            );
            if let BerObjectContent::OctetString(signature) = &signature_element.content {
                println!("Signature successfully extracted");
                return Ok(signature.to_vec());
            }
        }
    }
    println!("Failed to extract signature from SignerInfo");
    Err("Failed to extract signature".into())
}

fn extract_public_key_bytes(raw_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Extracting public key bytes");
    println!(
        "Raw key (first 50 bytes): {:?}",
        &raw_key[..50.min(raw_key.len())]
    );

    let (_, spki) = parse_der(raw_key)?;
    print_asn1_structure(&spki, 0);

    if let BerObjectContent::Sequence(spki_seq) = &spki.content {
        println!("SPKI Sequence length: {}", spki_seq.len());
        if spki_seq.len() == 2 {
            if let BerObjectContent::BitString(_, bit_string) = &spki_seq[1].content {
                println!("BitString length: {}", bit_string.data.len());
                if !bit_string.data.is_empty() {
                    println!("Public key successfully extracted");
                    // For ECDSA, we need to ensure the key is in the correct format
                    let point = EncodedPoint::from_bytes(&bit_string.data)?;
                    return Ok(point.as_bytes().to_vec());
                }
            }
        }
    }

    println!("Failed to extract public key bytes");
    Err("Failed to extract public key bytes".into())
}

fn prepare_auth_attr_for_hash(authenticated_attributes: &[u8]) -> Vec<u8> {
    let mut auth_attr_for_hash = Vec::new();
    auth_attr_for_hash.extend_from_slice(&[0x31]); // SET OF tag
    if authenticated_attributes.len() > 127 {
        auth_attr_for_hash.extend_from_slice(&[0x82]); // Long form length
        auth_attr_for_hash.extend_from_slice(&(authenticated_attributes.len() as u16).to_be_bytes());
    } else {
        auth_attr_for_hash.push(authenticated_attributes.len() as u8);
    }
    auth_attr_for_hash.extend_from_slice(authenticated_attributes);
    auth_attr_for_hash
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Inizio verifica PKCS#7...");

    let pkcs7_data = fs::read(P7S_FILE_PATH)
        .map_err(|e| format!("Errore nella lettura del file P7S: {}", e))?;
    let pca_public_key = fs::read(PCA_PUBLIC_KEY_PATH)
        .map_err(|e| format!("Errore nella lettura della chiave pubblica PCA: {}", e))?;

    println!("Lunghezza dati PKCS#7: {}", pkcs7_data.len());
    println!("Lunghezza chiave pubblica PCA: {}", pca_public_key.len());

    match verify_pkcs7_signature(&pkcs7_data, &pca_public_key) {
        Ok((message, signer_name, pca_name)) => {
            println!("Verifica riuscita!");
            println!("Messaggio: {:?}", String::from_utf8_lossy(&message));
            println!("Firmatario: {}", signer_name);
            println!("PCA: {}", pca_name);
        },
        Err(e) => eprintln!("Verifica fallita: {}", e),
    }

    Ok(())
}