use base64::Engine;
use bitvec::prelude::*;
use sha2::Digest;
use cbc::cipher::BlockDecryptMut;
use cbc::cipher::generic_array::GenericArray;
use cbc::cipher::KeyIvInit;

//  Access Without Mycelium Software
fn main() {
    // Parsing the QR Code

    // Scan the QR code to get a Base64 encoded string.
    const QR_CODED: &str = "xEncEXICqz2G4K5wFxm5u7VTMx7Wp5IjAqDyq1j0znAR8l4L7cptfJWuvjPX2A";

    // Decode the Base64 encoded string to get exactly 46 bytes.
    // The Base64 variant used is designed for URLs as specified in RFC 4648, section 5.
    // https://www.rfc-editor.org/rfc/rfc4648#section-5
    let base64_engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD);
    let decoded: Vec<u8> = base64_engine.decode(QR_CODED).expect("Base64 decoding failed");

    assert_eq!(decoded.len(), 46);

    // The first 3 bytes are the magic cookie 0xC4 0x49 0xDC: decoded[0...2]
    assert_eq!(decoded[0..=2], [0xC4, 0x49, 0xDC]);

    // The next 3 bytes are the header bytes: H = decoded[3...5]
    let header = &decoded[3..=5];

    // The next 4 bytes is the random salt: SALT = decoded[6...9]
    let salt = &decoded[6..=9];

    // The next 32 bytes are the encrypted private key: E = decoded[10...41]
    let encrypted = &decoded[10..=41];

    // The next 4 bytes are the checksum: C = decoded[42...45]
    let checksum = &decoded[42..=45];

    // Decoding the 3 Header Bytes

    // Regard the header as an array of 24 bits and decode the following values
    let bits = header.view_bits::<Msb0>();

    // version = XXXX???? ???????? ????????: must be 1
    assert_eq!(bits[0], false);
    assert_eq!(bits[1], false);
    assert_eq!(bits[2], false);
    assert_eq!(bits[3], true);

    // network = ????X??? ???????? ????????: 0 = prodnet, 1 = testnet
    let network = bits[4];
    eprintln!("network = {:?}", if !network { "prod" } else { "test" });

    // content = ?????XXX ???????? ????????:
    // 000 = private key with uncompressed public key
    // 001 = private key with compressed public key
    // 010 = 128 bit master seed
    // 011 = 192 bit master seed
    // 100 = 256 bit master seed
    let content_type = bits[5..8].load_be::<u8>();
    let content_type_desc =
        match content_type {
            0 => "private key with uncompressed public key",
            1 => "private key with compressed public key",
            2 => "128 bit master seed",
            3 => "192 bit master seed",
            4 => "256 bit master seed",
            _ => panic!("Unknown content type")
        };
    eprintln!("content = {:?}", content_type_desc);

    // HN = ???????? XXXXX??? ????????: 0 <= HN <= 31
    let hn = bits[8..13].load_be::<u8>();
    assert!(hn <= 31);

    // Hr = ???????? ?????XXX XX??????: 1 <= Hr <= 31
    let hr = bits[13..18].load_be::<u8>();
    assert!(hr <= 31);

    // Hp = ???????? ???????? ??XXXXX?: 1 <= Hp <= 31
    let hp = bits[18..23].load_be::<u8>();
    assert!(hp <= 31);

    // reserved = ???????? ???????? ???????X: must be zero
    assert!(!bits[23]);

    // AES Key Derivation

    // Make the user enter a 15-character password using characters A-Z, all in upper case.
    const PASSWORD: &str = "OHQTLWUPDLFEUDB";

    // Convert the characters to 15 bytes using normal ASCII conversion
    let password = PASSWORD.as_bytes();

    // An implementations may use additional checksum characters for password integrity. They are not part of the AES key derivation.
    // https://github.com/mycelium-com/wallet-android/blob/48c4143403d94cf29a968f1510d714fd7c49efcf/bitlib/src/main/java/com/mrd/bitlib/crypto/MrdExport.java#L770..L779

    // Run scrypt using parameters N = 2^HN, r = Hr, p = Hp on the password bytes and SALT, to derive 32 bytes.
    // The 32 output bytes are used as the 256-bit AES key used for decryption.

    // NOTE: salt may not be valid UTF8 and cannot be casted safely into String
    // eprintln!("salt = {:?}", salt);
    let scrypt_params = scrypt::Params::new(hn, hr.into(), hp.into()).unwrap();
    let mut scrypt_pass: Vec<u8> = vec!(0; 32);
    let scrypt_result = scrypt::scrypt(password, salt, &scrypt_params, &mut scrypt_pass);
    // eprintln!("scrypt_result = {:?}", scrypt_result);
    scrypt_result.expect("AES key derivation failed");

    // The next 3 bytes are the header bytes: H = decoded[3...5]
    // FIXME: wrong instruction, probably an accidental copy-paste

    // Decrypting the Content Data

    // The decryption function is 256-bit AES in CBC mode.
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256Dec>;

    // Generate the AES initialization vector (IV) by doing a single round of SHA256 on the concatenation of SALT and C, and use the first 16 bytes of the output.
    let sha256_input = [salt, checksum].concat();
    let sha256_result = sha2::Sha256::digest(sha256_input.as_slice());
    // eprintln!("sha256_result = {:?}", sha256_result);
    let aes_iv = &sha256_result[0..16];
    // eprintln!("aes_iv = {:?}", aes_iv);

    // Split E into two 16-byte blocks E1 and E2.
    let mut blocks = [
        GenericArray::clone_from_slice(&encrypted[0..16]),
        GenericArray::clone_from_slice(&encrypted[16..32])
    ];

    // Do an AES block decryption of E1 into P1 using the derived AES key.
    // X-or the initialization vector onto P1: P1 = P1 xor IV
    // Do an AES block decryption of E2 into P2 using the derived AES key.
    // X-or E1 onto P2: P2 = P2 xor E1

    let aes_key = GenericArray::clone_from_slice(&*scrypt_pass);
    let aes_iv = GenericArray::clone_from_slice(aes_iv);

    // eprintln!("encrypted = {:?}", blocks);
    Aes256CbcDec::new(&aes_key, &aes_iv).decrypt_blocks_mut(&mut blocks);
    // eprintln!("decrypted = {:?}", blocks);

    // The 32 byte plaintext data is the concatenation of P1 and P2: P = P1 || P2
    let decrypted = blocks.concat();
    assert_eq!(decrypted.len(), 32);

    // If content is 000 or 001 the 32 bytes are a private key.
    // If content is 010 the first 16 bytes are a master seed.
    // If content is 011 the first 24 bytes are a master seed.
    // If content is 100 the 32 bytes are a master seed.

    let secret =
        match content_type {
            0 | 1 => &decrypted,
            2 => &decrypted[0..16],
            3 => &decrypted[0..24],
            4 => &decrypted,
            _ => panic!("Unknown content type")
        };

    // https://github.com/mycelium-com/wallet-android/blob/48c4143403d94cf29a968f1510d714fd7c49efcf/bitlib/src/main/java/com/mrd/bitlib/crypto/InMemoryPrivateKey.java#L386..L400
    const SECRET: &str = "Ky8fmGN3jArYcyAqj3XSs9Q4pxxutJAwqAmGMVqBigYnpgDHegZh";
    let decoded_secret = &(bs58::decode(SECRET).into_vec().unwrap())[1..33];
    assert_eq!(secret, decoded_secret);

    // Verifying the Checksum

    // Convert the generated bitcoin address to an array of ASCII bytes
    // FIXME: there were no addresses generated so far, only the secret decrypted
    // meaning: key.getPublicKey().toAddress(network, AddressType.P2PKH)
    // https://github.com/mycelium-com/wallet-android/blob/48c4143403d94cf29a968f1510d714fd7c49efcf/bitlib/src/main/java/com/mrd/bitlib/crypto/MrdExport.java#L786

    const P2PKH_ADDRESS: &[u8] = "1Ba8Fh72zSrgBMj81UDCKUGz17HipEC1xM".as_bytes();

    // Do a single SHA256 operation on the array of bytes
    let secret_sha256 = sha2::Sha256::digest(P2PKH_ADDRESS);

    // The checksum is the first 4 bytes of the output
    let secret_checksum = &secret_sha256[0..4];

    // Verify that the calculated checksum equals C. If a wrong password was entered the checksums will not match.
    assert_eq!(secret_checksum, checksum);

    eprintln!("Backup decrypted");
}
