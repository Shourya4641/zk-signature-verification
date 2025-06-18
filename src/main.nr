use dep::ecrecover;
use dep::std;

global SECP256K1_N: Field = 0xFFFFFFFFFFFFFFFF * 2.pow_32(192)
    + 0xFFFFFFFFFFFFFFFE * 2.pow_32(128)
    + 0xBAAEDCE6AF48A03B * 2.pow_32(64)
    + 0xBFD25E8CD0364141;
global SECP256K1_P: Field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

fn main(
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    hashed_message: [u8; 32],
    expected_address: Field,
    nonce: Field,
    timestamp: Field,
    max_timestamp: Field,
) {
    validate_inputs(
        pub_key_x,
        pub_key_y,
        signature,
        hashed_message,
        expected_address,
        nonce,
        timestamp,
        max_timestamp,
    );

    check_public_key_on_curve(pub_key_x, pub_key_y);
    check_signature_bound(signature);
    check_signature_malleability(signature);

    let address = perform_secure_ecrecover(pub_key_x, pub_key_y, signature, hashed_message);

    perform_final_verification(address, expected_address, nonce, timestamp);
}

////////////////////////VALIDATION FUNCTIONS////////////////////////////

fn validate_inputs(
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    hashed_message: [u8; 32],
    expected_address: Field,
    nonce: Field,
    timestamp: Field,
    max_timestamp: Field,
) {
    assert(!is_zero_array_32(pub_key_x), "ERR_001: Public key X cannot be zero");
    assert(!is_zero_array_32(pub_key_y), "ERR_002: Public key Y cannot be zero");
    assert(!is_zero_array_64(signature), "ERR_003: Signature cannot be zero");
    assert(!is_zero_array_32(hashed_message), "ERR_004: Message Hash cannot be zero");
    assert(expected_address != 0, "ERR_005: Expected Address cannot be zero");
    assert(nonce != 0, "ERR_006: Nonce cannot be zero");

    assert(!timestamp.lt(0), "ERR_007: Timestamp should be more than zero");
    assert(!max_timestamp.lt(timestamp), "ERR_008: Max timestamp must be greater than timestamp");
}

fn check_public_key_on_curve(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) {
    let x = bytes_to_field(pub_key_x);
    let y = bytes_to_field(pub_key_y);

    assert(!x.lt(0), "ERR_009: Public key X must be greater than zero");
    assert(!y.lt(0), "ERR_010: Public key Y must be greater than zero");

    assert(x.lt(SECP256K1_P), "ERR_011: Public key X exceeds curve modulus");
    assert(y.lt(SECP256K1_P), "ERR_012: Public key Y exceeds curve modulus");

    let y_square = mulmod(y, y, SECP256K1_P);
    let x_cube = mulmod(mulmod(x, x, SECP256K1_P), x, SECP256K1_P);
    let right = addmod(x_cube, 7, SECP256K1_P);

    assert(y_square == right, "ERR_013: Public key not on secp256k1 curve");
}

fn check_signature_bound(signature: [u8; 64]) {
    let mut r_bytes: [u8; 32] = [0; 32];
    let mut s_bytes: [u8; 32] = [0; 32];

    for i in 0..32 {
        r_bytes[i] = signature[i];
        s_bytes[i] = signature[i + 32];
    }

    let r = bytes_to_field(r_bytes);
    let s = bytes_to_field(s_bytes);

    assert(!r.lt(0), "ERR_014: Signature r component must be greater than zero");
    assert(!s.lt(0), "ERR_015: Signature s component must be greater than zero");
    assert(r.lt(SECP256K1_N), "ERR_016: Signature r component exceeds curve order");
    assert(s.lt(SECP256K1_N), "ERR_017: Signature s component exceeds curve order");
}

fn check_signature_malleability(signature: [u8; 64]) {
    let mut s_bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        s_bytes[i] = signature[i + 32];
    }

    let s = bytes_to_field(s_bytes);
    let half_n = SECP256K1_N / 2;

    assert(
        (s as u64) < (half_n as u64),
        "ERR_018: Signature s component too high (malleability risk)",
    );
}

fn perform_secure_ecrecover(
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    hashed_message: [u8; 32],
) -> Field {
    let recovered_address = ecrecover::ecrecover(pub_key_x, pub_key_y, signature, hashed_message);

    assert(recovered_address != 0, "ERR_022: ECDSA recovery failed");

    let max_eth_address: Field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    assert(
        (recovered_address as u64) < (max_eth_address as u64),
        "ERR_023: Invalid Ethereum address format",
    );

    recovered_address
}

fn perform_final_verification(
    recovered_address: Field,
    expected_address: Field,
    nonce: Field,
    timestamp: Field,
) {
    assert(recovered_address == expected_address, "ERR_024: Address verification failed");

    let commitment = std::hash::pedersen_hash([recovered_address, nonce, timestamp]);
    assert(commitment != 0, "ERR_025: Commitment hash generation failed");
}

//////////////////UTILITY FUNCTIONS/////////////////////

fn is_zero_array_32(arr: [u8; 32]) -> bool {
    let mut is_zero = true;
    for i in 0..32 {
        if arr[i] != 0 {
            is_zero = false;
        }
    }
    is_zero
}

fn is_zero_array_64(arr: [u8; 64]) -> bool {
    let mut is_zero = true;
    for i in 0..64 {
        if arr[i] != 0 {
            is_zero = false;
        }
    }
    is_zero
}

fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

fn addmod(a: Field, b: Field, m: Field) -> Field {
    let a_int: u64 = a as u64;
    let b_int: u64 = b as u64;
    let m_int: u64 = m as u64;
    ((a_int + b_int) % m_int) as Field
}

fn mulmod(a: Field, b: Field, m: Field) -> Field {
    let a_int: u64 = a as u64;
    let b_int: u64 = b as u64;
    let m_int: u64 = m as u64;
    ((a_int * b_int) % m_int) as Field
}

#[test]
fn test_main() {
    // main(1, 2);

    // Uncomment to make test fail
    // main(1, 1);
}
