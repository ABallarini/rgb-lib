//! Cryptographic helpers: SHA-256 hashing, Ed25519 operation keys and signatures, and the
//! end-to-end encryption of the data exchanged with a counterparty.
//!
//! The encryption format is the one fixed by the proxy protocol v1.0 changes specification
//! (`v1.0-changes-spec.md`, Appendix A) so that independent clients interoperate, but it is a
//! client-side layer that the proxy never inspects.
//!
//! All operation keys are derived from Ed25519 key pairs, one per counterparty. The symmetric key
//! used to encrypt data is derived, by each party independently, from their respective pairs of
//! "own X25519 private key" + "counterpart X25519 public key" via ECDH, and then run through HKDF.
//! Ed25519 keys are converted to X25519 via the standard Curve25519 birational map. See
//! `v1.0-changes-spec.md`, A.3 (key derivation), for the details.
//!
//! The data is encrypted in fixed-size 64 KiB plaintext chunks, each as an independent
//! XChaCha20-Poly1305 one-shot AEAD operation, with a deterministic per-chunk nonce derived from
//! the plaintext hash. The whole blob is prefixed with a single-byte encryption-format version.
//! Both directions are streamed one chunk at a time, so memory use does not depend on the payload
//! size. See `v1.0-changes-spec.md`, 4.2 (payload encryption on the wire) for what the proxy sees,
//! and A.4 (chunking), A.5 (nonce) and A.6 (caveats) for the full rationale.

use super::*;

/// Current encryption-format version, also bound into the HKDF `info` label.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) const ENC_VERSION: u8 = 0x01;
/// Plaintext chunk size (64 KiB, binary).
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) const CHUNK: usize = 65536;
/// XChaCha20-Poly1305 authentication tag length (bytes).
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
const TAG: usize = 16;
/// Ciphertext chunk size for a full plaintext chunk.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
const ENC_CHUNK: usize = CHUNK + TAG;
/// HKDF `info` label for the symmetric encryption key.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
const INFO_ENC: &[u8] = b"rgb-proxy-server/enc/v1";
/// HKDF `info` label for the media-id keying material.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
const INFO_MEDIA_ID: &[u8] = b"rgb-proxy-server/enc/v1/media-id";
/// HKDF `info` label for the witness seal blinding factor.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
const INFO_SEAL_BLINDING: &[u8] = b"rgb-proxy-server/enc/v1/seal-blinding";
/// Domain separation prefix of the invoice ID.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
const INVOICE_ID_PREFIX: &str = "rgb-proxy-server/invoice/v1";
/// Domain separation prefix of the transfer ID.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
const TRANSFER_ID_PREFIX: &str = "rgb-proxy-server/transfer/v1";

/// Symmetric key material derived from a shared secret.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) struct DerivedKeys {
    /// XChaCha20-Poly1305 key for consignment / media / signed TX.
    pub(crate) sym_key: [u8; 32],
    /// HMAC key used to derive per-media identifiers.
    kmid: [u8; 32],
    /// Blinding factor of the recipient witness seal (see `v1.0-changes-spec.md` A.11).
    #[cfg_attr(
        all(target_arch = "wasm32", not(feature = "_online")),
        allow(dead_code)
    )]
    pub(crate) seal_blinding: u64,
}

/// Generate a random Ed25519 signing key.
///
/// The 32-byte seed is drawn straight from the OS CSPRNG rather than from the user-space thread
/// RNG: this is long-lived key material, and the OS source needs no reseeding after a `fork`. The
/// raw bytes are handed to dalek directly, avoiding the `rand_core` version mismatch between the
/// project's `rand` and `ed25519-dalek`.
pub(crate) fn gen_ed25519() -> SigningKey {
    let mut seed = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut seed)
        .expect("OS randomness source unavailable");
    SigningKey::from_bytes(&seed)
}

/// Derive an Ed25519 signing key from a 32-byte seed (which is the Ed25519 secret key expansion
/// input).
///
/// Used by multisig so all cosigners derive the same key from a hub-shared seed.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn ed25519_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Parse a raw 32-byte Ed25519 public key.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidPubkey {
        details: String::from("invalid Ed25519 public key length"),
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| Error::InvalidPubkey {
        details: format!("invalid Ed25519 public key: {e}"),
    })
}

/// Convert an Ed25519 verifying key to the corresponding X25519 public key.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
fn ed25519_pub_to_x25519(pk: &VerifyingKey) -> X25519Public {
    X25519Public::from(pk.to_montgomery().to_bytes())
}

/// Convert an Ed25519 signing key to the corresponding X25519 secret.
///
/// The X25519 scalar is `SHA-512(seed)[0..32]`; X25519 applies the standard Curve25519 clamping when
/// computing the Diffie-Hellman, so feeding the unclamped bytes yields the correct result.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
fn ed25519_secret_to_x25519(sk: &SigningKey) -> X25519Secret {
    let hash = Sha512::digest(sk.to_bytes());
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    X25519Secret::from(scalar)
}

/// Derive the symmetric key material shared between the two parties.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn derive_shared(
    own_sk: &SigningKey,
    their_pk: &VerifyingKey,
) -> Result<DerivedKeys, Error> {
    let secret = ed25519_secret_to_x25519(own_sk);
    let public = ed25519_pub_to_x25519(their_pk);
    let shared = secret.diffie_hellman(&public);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(INFO_ENC, &mut sym_key)
        .expect("HKDF expand to 32 bytes");
    let mut kmid = [0u8; 32];
    hk.expand(INFO_MEDIA_ID, &mut kmid)
        .expect("HKDF expand to 32 bytes");
    let mut blinding = [0u8; 8];
    hk.expand(INFO_SEAL_BLINDING, &mut blinding)
        .expect("HKDF expand to 8 bytes");

    Ok(DerivedKeys {
        sym_key,
        kmid,
        seal_blinding: u64::from_le_bytes(blinding),
    })
}

#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
impl DerivedKeys {
    /// Derive the per-media identifier for a given plaintext media digest (hex-encoded SHA-256).
    pub(crate) fn media_id(&self, media_digest_hex: &str) -> String {
        let mut mac = <SimpleHmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.kmid)
            .expect("HMAC accepts any key length");
        mac.update(media_digest_hex.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Compute the ID of an invoice on the proxy from its beneficiary (as encoded in the invoice) and
/// its hex-encoded pubkey.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn invoice_id(beneficiary: &str, recipient_pk_hex: &str) -> String {
    hex::encode(sha256_digest(
        format!("{INVOICE_ID_PREFIX}{beneficiary}{recipient_pk_hex}").as_bytes(),
    ))
}

/// Compute the ID of a transfer on the proxy from the ID of the invoice it pays and the
/// hex-encoded pubkey of the sender operation.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn transfer_id(invoice_id: &str, sender_pk_hex: &str) -> String {
    hex::encode(sha256_digest(
        format!("{TRANSFER_ID_PREFIX}{invoice_id}{sender_pk_hex}").as_bytes(),
    ))
}

/// Number of leading zero bits of a digest, starting from the most significant bit of its first
/// byte.
#[cfg(feature = "_online")]
fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        bits += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    bits
}

/// Find a proof of work nonce for a `consignment.post` call, such that
/// `SHA-256(transfer_id ‖ pow_timestamp ‖ pow_nonce)` has at least `difficulty` leading zero bits
/// (see `v1.0-changes-spec.md` C.2).
#[cfg(feature = "_online")]
pub(crate) fn solve_pow(transfer_id: &str, pow_timestamp: &str, difficulty: u32) -> String {
    let prefix = format!("{transfer_id}{pow_timestamp}");
    (0u64..)
        .map(|n| n.to_string())
        .find(|nonce| {
            difficulty == 0
                || leading_zero_bits(&sha256_digest(format!("{prefix}{nonce}").as_bytes()))
                    >= difficulty
        })
        .expect("a nonce is eventually found")
}

/// Build the 24-byte per-chunk nonce.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
fn chunk_nonce(base: &[u8], counter: u32, is_final: bool) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..19].copy_from_slice(base);
    nonce[19..23].copy_from_slice(&counter.to_be_bytes());
    nonce[23] = is_final as u8;
    nonce
}

/// Read into `buf` until it is full or `reader` is exhausted. Fewer bytes than `buf.len()` are
/// returned only at EOF, never because of a single short read.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
fn fill_upto(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize, Error> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // the reader rejected its input (e.g. a base64 decoder fed malformed data): report it
            // as a malformed blob
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(Error::InvalidEncryptedBlob {
                    details: e.to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

/// Encrypt the plaintext read from `reader` into `writer` as a chunked, version-prefixed blob.
///
/// `plaintext_sha256` is the 32 raw bytes of the SHA-256 of the full plaintext; its last 19 bytes
/// form the per-message nonce base. The plaintext is consumed one chunk at a time, looking one
/// chunk ahead to flag the final one, so memory use is bounded by two plaintext chunks plus one
/// ciphertext chunk regardless of the payload size.
#[cfg(feature = "_online")]
pub(crate) fn encrypt_stream(
    mut reader: impl Read,
    mut writer: impl Write,
    sym_key: &[u8; 32],
    plaintext_sha256: &[u8; 32],
) -> Result<(), Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(sym_key).expect("32-byte key");
    let base = &plaintext_sha256[13..32];
    writer.write_all(&[ENC_VERSION])?;

    let mut cur = vec![0u8; CHUNK];
    let mut next = vec![0u8; CHUNK];
    let mut cur_len = fill_upto(&mut reader, &mut cur)?;
    let mut counter: u32 = 0;
    loop {
        let next_len = fill_upto(&mut reader, &mut next)?;
        let is_final = next_len == 0;
        let nonce = chunk_nonce(base, counter, is_final);
        let ct = cipher
            .encrypt(&XNonce::from(nonce), &cur[..cur_len])
            .expect("chunk size is within XChaCha20-Poly1305 limits");
        writer.write_all(&ct)?;
        if is_final {
            writer.flush()?;
            return Ok(());
        }
        counter += 1;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
}

/// Decrypt the version-prefixed chunked blob read from `reader`, as produced by
/// [`encrypt_stream`], into `writer`.
///
/// The ciphertext is consumed one chunk at a time, looking one chunk ahead to detect the final
/// one. Each chunk is authenticated and written out before the next is read, so on failure
/// `writer` may already hold the plaintext chunks preceding the error: the caller must discard its
/// output in that case.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn decrypt_stream(
    mut reader: impl Read,
    mut writer: impl Write,
    sym_key: &[u8; 32],
    plaintext_sha256: &[u8; 32],
) -> Result<(), Error> {
    let mut version = [0u8; 1];
    if fill_upto(&mut reader, &mut version)? == 0 {
        return Err(Error::InvalidEncryptedBlob {
            details: String::from("empty encrypted blob"),
        });
    }
    if version[0] != ENC_VERSION {
        return Err(Error::InvalidEncryptedBlob {
            details: format!("unsupported encryption version {}", version[0]),
        });
    }

    let cipher = XChaCha20Poly1305::new_from_slice(sym_key).expect("32-byte key");
    let base = &plaintext_sha256[13..32];

    let mut cur = vec![0u8; ENC_CHUNK];
    let mut next = vec![0u8; ENC_CHUNK];
    let mut cur_len = fill_upto(&mut reader, &mut cur)?;
    let mut counter: u32 = 0;
    loop {
        if cur_len < TAG {
            return Err(Error::InvalidEncryptedBlob {
                details: String::from("truncated encrypted blob"),
            });
        }
        let next_len = fill_upto(&mut reader, &mut next)?;
        let is_final = next_len == 0;
        let nonce = chunk_nonce(base, counter, is_final);
        let pt = cipher
            .decrypt(&XNonce::from(nonce), &cur[..cur_len])
            .map_err(|_| Error::InvalidEncryptedBlob {
                details: String::from("authentication failed"),
            })?;
        writer.write_all(&pt)?;
        if is_final {
            writer.flush()?;
            return Ok(());
        }
        counter += 1;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
}

/// In-memory counterpart of [`encrypt_stream`], for small payloads such as the signed TX.
#[cfg(feature = "_online")]
pub(crate) fn encrypt_blob(
    plaintext: &[u8],
    sym_key: &[u8; 32],
    plaintext_sha256: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let n_chunks = plaintext.len().div_ceil(CHUNK).max(1);
    let mut out = Vec::with_capacity(1 + plaintext.len() + n_chunks * TAG);
    encrypt_stream(plaintext, &mut out, sym_key, plaintext_sha256)?;
    Ok(out)
}

/// In-memory counterpart of [`decrypt_stream`], for small payloads such as the signed TX.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn decrypt_blob(
    blob: &[u8],
    sym_key: &[u8; 32],
    plaintext_sha256: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(blob.len());
    decrypt_stream(blob, &mut out, sym_key, plaintext_sha256)?;
    Ok(out)
}

/// The symmetric key shared with the counterparty, derived from an operation seed and the
/// counterparty's hex-encoded Ed25519 pubkey.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn shared_keys(
    own_seed: &[u8],
    counterparty_pubkey_hex: &str,
) -> Result<DerivedKeys, Error> {
    let seed: [u8; 32] = own_seed.try_into().map_err(|_| Error::Internal {
        details: s!("invalid own secret key"),
    })?;
    let own_sk = ed25519_from_seed(&seed);
    let counterparty_vk =
        verifying_key_from_bytes(&hex::decode(counterparty_pubkey_hex).map_err(|_| {
            Error::Internal {
                details: s!("invalid counterparty pubkey"),
            }
        })?)?;
    derive_shared(&own_sk, &counterparty_vk)
}

/// The symmetric key shared with the counterparty and the raw bytes of the expected plaintext
/// hash, as the encryption primitives take them.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn shared_key_and_hash(
    own_seed: &[u8],
    counterparty_pubkey_hex: &str,
    hash_hex: &str,
) -> Result<([u8; 32], [u8; 32]), Error> {
    let derived = shared_keys(own_seed, counterparty_pubkey_hex)?;
    let hash_raw = decode_hash_hex(hash_hex)?;
    Ok((derived.sym_key, hash_raw))
}

/// Verify a downloaded blob against its expected plaintext hash, first decrypting it with the key
/// shared with the counterparty as dictated by `encryption`, the mode the payload is expected in:
/// the recipient's invoice preference for consignments and media, always `Required` for the signed
/// TX. For `Optional` the encrypted form is tried first, falling back to cleartext; for
/// `Unsupported` the blob is taken as cleartext. Anything that doesn't match the hash afterwards
/// (e.g. a blob encrypted despite `Unsupported`) is rejected.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn decrypt_blob_with_shared_key(
    raw: Vec<u8>,
    encryption: Encryption,
    own_seed: &[u8],
    counterparty_pubkey_hex: &str,
    hash_hex: &str,
) -> Result<Vec<u8>, Error> {
    let (sym_key, hash_raw) = shared_key_and_hash(own_seed, counterparty_pubkey_hex, hash_hex)?;

    // When `raw` is returned unmodified it might still be encrypted.
    // The plaintext hash check below catches these cases as well.
    let plaintext = match encryption {
        Encryption::Unsupported => raw,
        Encryption::Required => decrypt_blob(&raw, &sym_key, &hash_raw)?,
        Encryption::Optional => match decrypt_blob(&raw, &sym_key, &hash_raw) {
            Ok(p) => p,
            Err(_) => raw,
        },
    };
    if hex::encode(sha256_digest(&plaintext)) != hash_hex {
        return Err(Error::HashMismatch);
    }
    Ok(plaintext)
}

/// In-memory counterpart of the streaming media decryption: the base64 payload a proxy delivers is
/// decoded, decrypted and verified against the expected plaintext hash, all in memory.
#[cfg_attr(feature = "_online", allow(dead_code))]
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn decrypt_b64_blob_with_shared_key(
    payload_b64: &str,
    encryption: Encryption,
    own_seed: &[u8],
    counterparty_pubkey_hex: &str,
    hash_hex: &str,
) -> Result<Vec<u8>, Error> {
    use base64::{Engine as _, engine::general_purpose};

    let raw =
        general_purpose::STANDARD
            .decode(payload_b64)
            .map_err(|e| Error::InvalidEncryptedBlob {
                details: e.to_string(),
            })?;
    decrypt_blob_with_shared_key(raw, encryption, own_seed, counterparty_pubkey_hex, hash_hex)
}

/// Encrypt the file at `plaintext_path` for `sym_key` into a fresh temp file and return it (kept
/// alive by the caller for the duration of the upload). The file is streamed through
/// [`encrypt_stream`], so memory use does not depend on its size.
#[cfg(feature = "_online")]
pub(crate) fn encrypt_to_tempfile(
    plaintext_path: &Path,
    sym_key: &[u8; 32],
    plaintext_hash_hex: &str,
) -> Result<tempfile::NamedTempFile, Error> {
    let plaintext_sha256 = decode_hash_hex(plaintext_hash_hex)?;
    let plaintext = fs::File::open(plaintext_path)?;
    let mut tmp = tempfile::NamedTempFile::new()?;
    encrypt_stream(plaintext, &mut tmp, sym_key, &plaintext_sha256)?;
    Ok(tmp)
}

/// Sign a message with an Ed25519 signing key, returning the raw 64-byte signature.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn sign_ed25519(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
    sk.sign(msg).to_bytes()
}

/// Verify an Ed25519 signature (raw 64 bytes) over `msg` against `pk`.
#[cfg(feature = "_online")]
pub(crate) fn verify_ed25519(pk: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig);
    pk.verify(msg, &sig).is_ok()
}

/// Compute the SHA-256 digest of `data`.
pub(crate) fn sha256_digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Decode a hex-encoded SHA-256 digest, as hashes are stored and exchanged with the proxy, into
/// the bytes the encryption primitives work on.
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) fn decode_hash_hex(hash_hex: &str) -> Result<[u8; 32], Error> {
    hex::decode(hash_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Internal {
            details: String::from("invalid plaintext hash"),
        })
}

#[cfg(all(test, feature = "_online"))]
mod tests {
    use super::*;

    fn keys() -> (SigningKey, SigningKey) {
        (gen_ed25519(), gen_ed25519())
    }

    #[test]
    fn shared_secret_matches_both_sides() {
        let (a, b) = keys();
        let ka = derive_shared(&a, &b.verifying_key()).unwrap();
        let kb = derive_shared(&b, &a.verifying_key()).unwrap();
        assert_eq!(ka.sym_key, kb.sym_key);
        assert_eq!(ka.kmid, kb.kmid);
        assert_eq!(ka.seal_blinding, kb.seal_blinding);
    }

    #[test]
    fn seal_blinding_differs_per_key_pair() {
        let (a, b) = keys();
        let c = gen_ed25519();
        let kab = derive_shared(&a, &b.verifying_key()).unwrap();
        let kac = derive_shared(&a, &c.verifying_key()).unwrap();
        assert_ne!(kab.seal_blinding, kac.seal_blinding);
    }

    #[test]
    fn proxy_ids() {
        let invoice_id = invoice_id("bcrt:utxob:abc", "aa");
        assert_eq!(
            invoice_id,
            hex::encode(sha256_digest(
                b"rgb-proxy-server/invoice/v1bcrt:utxob:abcaa"
            ))
        );
        assert_eq!(
            transfer_id(&invoice_id, "bb"),
            hex::encode(sha256_digest(
                format!("rgb-proxy-server/transfer/v1{invoice_id}bb").as_bytes()
            ))
        );
    }

    #[test]
    fn pow() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x10]), 19);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
        // any nonce satisfies difficulty 0
        assert_eq!(solve_pow("tid", "123", 0), "0");
        for difficulty in [1, 8, 12] {
            let nonce = solve_pow("tid", "123", difficulty);
            let digest = sha256_digest(format!("tid123{nonce}").as_bytes());
            assert!(leading_zero_bits(&digest) >= difficulty);
        }
    }

    #[test]
    fn media_id_matches_both_sides() {
        let (a, b) = keys();
        let ka = derive_shared(&a, &b.verifying_key()).unwrap();
        let kb = derive_shared(&b, &a.verifying_key()).unwrap();
        let digest = hex::encode([7u8; 32]);
        assert_eq!(ka.media_id(&digest), kb.media_id(&digest));
    }

    #[test]
    fn blob_roundtrip() {
        let (a, b) = keys();
        let k = derive_shared(&a, &b.verifying_key()).unwrap();
        for len in [
            0usize,
            1,
            100,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            2 * CHUNK,
            3 * CHUNK + 8192,
        ] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let hash = sha256_digest(&pt);
            let blob = encrypt_blob(&pt, &k.sym_key, &hash).unwrap();
            // version byte + one tag per chunk
            let n_chunks = if len == 0 { 1 } else { len.div_ceil(CHUNK) };
            assert_eq!(blob.len(), 1 + len + n_chunks * TAG);
            assert_eq!(blob[0], ENC_VERSION);
            let dec = decrypt_blob(&blob, &k.sym_key, &hash).unwrap();
            assert_eq!(dec, pt);
        }
    }

    #[test]
    fn base64_blob_decrypts_against_the_contract_digest() {
        use base64::{Engine as _, engine::general_purpose};

        let (a, b) = keys();
        let pt = b"media payload";
        let hash = sha256_digest(pt);
        let k = derive_shared(&a, &b.verifying_key()).unwrap();
        let blob = encrypt_blob(pt, &k.sym_key, &hash).unwrap();
        let b64 = general_purpose::STANDARD.encode(&blob);
        let seed = a.to_bytes();
        let peer = hex::encode(b.verifying_key().to_bytes());

        let dec = decrypt_b64_blob_with_shared_key(
            &b64,
            Encryption::Required,
            &seed,
            &peer,
            &hex::encode(hash),
        )
        .unwrap();
        assert_eq!(dec, pt);

        // malformed base64 is a malformed payload
        assert!(matches!(
            decrypt_b64_blob_with_shared_key(
                "not base64!",
                Encryption::Required,
                &seed,
                &peer,
                &hex::encode(hash)
            ),
            Err(Error::InvalidEncryptedBlob { .. })
        ));
        // a payload treated as cleartext that does not match the contract digest is refused
        assert!(matches!(
            decrypt_b64_blob_with_shared_key(
                &b64,
                Encryption::Unsupported,
                &seed,
                &peer,
                &hex::encode([0u8; 32])
            ),
            Err(Error::HashMismatch)
        ));
    }

    #[test]
    fn decrypt_rejects_tamper_and_wrong_key() {
        let (a, b) = keys();
        let k = derive_shared(&a, &b.verifying_key()).unwrap();
        let pt = vec![42u8; CHUNK + 10];
        let hash = sha256_digest(&pt);
        let mut blob = encrypt_blob(&pt, &k.sym_key, &hash).unwrap();
        // tamper a ciphertext byte
        blob[5] ^= 0xff;
        assert!(decrypt_blob(&blob, &k.sym_key, &hash).is_err());

        // wrong key
        let blob = encrypt_blob(&pt, &k.sym_key, &hash).unwrap();
        let wrong = [9u8; 32];
        assert!(decrypt_blob(&blob, &wrong, &hash).is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = gen_ed25519();
        let msg = b"rgb-proxy ack message";
        let sig = sign_ed25519(&sk, msg);
        assert!(verify_ed25519(&sk.verifying_key(), msg, &sig));
        assert!(!verify_ed25519(&sk.verifying_key(), b"other", &sig));
    }

    /// Reader handing out one byte per call, to exercise short reads.
    struct ByteAtATime<'a>(&'a [u8]);

    impl Read for ByteAtATime<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match (self.0.split_first(), buf.first_mut()) {
                (Some((&byte, rest)), Some(slot)) => {
                    *slot = byte;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    #[test]
    fn stream_matches_blob_through_short_reads() {
        let (a, b) = keys();
        let k = derive_shared(&a, &b.verifying_key()).unwrap();
        for len in [
            0usize,
            1,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            2 * CHUNK,
            2 * CHUNK + 7,
        ] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let hash = sha256_digest(&pt);
            let blob = encrypt_blob(&pt, &k.sym_key, &hash).unwrap();
            // the ciphertext is deterministic, whatever the read pattern of the source
            let mut streamed = Vec::new();
            encrypt_stream(ByteAtATime(&pt), &mut streamed, &k.sym_key, &hash).unwrap();
            assert_eq!(streamed, blob);
            let mut dec = Vec::new();
            decrypt_stream(ByteAtATime(&blob), &mut dec, &k.sym_key, &hash).unwrap();
            assert_eq!(dec, pt);
        }
    }

    #[test]
    fn tempfile_roundtrip() {
        let (a, b) = keys();
        let k = derive_shared(&a, &b.verifying_key()).unwrap();
        let pt: Vec<u8> = (0..CHUNK + 123).map(|i| (i % 253) as u8).collect();
        let mut plain = tempfile::NamedTempFile::new().unwrap();
        plain.write_all(&pt).unwrap();
        let hash = sha256_digest(&pt);
        let enc = encrypt_to_tempfile(plain.path(), &k.sym_key, &hex::encode(hash)).unwrap();
        let blob = fs::read(enc.path()).unwrap();
        assert_eq!(blob, encrypt_blob(&pt, &k.sym_key, &hash).unwrap());
        assert_eq!(decrypt_blob(&blob, &k.sym_key, &hash).unwrap(), pt);
    }

    #[test]
    fn decrypt_rejects_truncation() {
        let (a, b) = keys();
        let k = derive_shared(&a, &b.verifying_key()).unwrap();
        let pt = vec![3u8; CHUNK + 10];
        let hash = sha256_digest(&pt);
        let blob = encrypt_blob(&pt, &k.sym_key, &hash).unwrap();
        // cut right after the first chunk: now seen as final, its nonce no longer matches
        assert!(decrypt_blob(&blob[..1 + ENC_CHUNK], &k.sym_key, &hash).is_err());
        // cut inside the last chunk, leaving less than a tag
        assert!(decrypt_blob(&blob[..1 + ENC_CHUNK + TAG - 1], &k.sym_key, &hash).is_err());
        // cut inside the last chunk, leaving a full tag but missing data
        assert!(decrypt_blob(&blob[..blob.len() - 1], &k.sym_key, &hash).is_err());
    }
}
