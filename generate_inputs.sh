#!/bin/bash

input_file="inputs.txt"
output_file="Prover.toml"

# Required array sizes
HASH_SIZE=32
PUBKEY_SIZE=32
SIG_SIZE=64

# Extract value from inputs.txt for a given key
extract_value() {
    local key=$1
    grep "^$key\s*=" "$input_file" | sed -E 's/^[^=]+= *"(.*)"/\1/'
}

# Convert hex string (without 0x) to quoted decimal byte array of fixed size
hex_to_fixed_dec_quoted_array() {
    local hexstr=$1
    local size=$2
    local len=${#hexstr}
    local arr=()

    for (( i=0; i<len && ${#arr[@]}<size; i+=2 )); do
        local hexbyte="${hexstr:i:2}"
        local dec=$((16#$hexbyte))
        arr+=("\"$dec\"")
    done

    # Pad with "0" if less than required size
    while [ ${#arr[@]} -lt $size ]; do
        arr+=("\"0\"")
    done

    echo "["$(IFS=,; echo "${arr[*]}")"]"
}

# Get values
expected_address=$(extract_value expected_address)
nonce=$(extract_value nonce)
hashed_message=$(extract_value hashed_message)
pub_key_x=$(extract_value pub_key_x)
pub_key_y=$(extract_value pub_key_y)
signature=$(extract_value signature)

# Strip '0x' if present
hashed_message=${hashed_message#0x}
pub_key_x=${pub_key_x#0x}
pub_key_y=${pub_key_y#0x}
signature=${signature#0x}

# Remove the last byte (v) from signature — 2 hex chars
signature=${signature:0:${#signature}-2}

# Convert hex to fixed-length decimal arrays
hashed_message_arr=$(hex_to_fixed_dec_quoted_array "$hashed_message" $HASH_SIZE)
pub_key_x_arr=$(hex_to_fixed_dec_quoted_array "$pub_key_x" $PUBKEY_SIZE)
pub_key_y_arr=$(hex_to_fixed_dec_quoted_array "$pub_key_y" $PUBKEY_SIZE)
signature_arr=$(hex_to_fixed_dec_quoted_array "$signature" $SIG_SIZE)

# Write TOML output
cat > "$output_file" <<EOF
expected_address = "$expected_address"
hashed_message = $hashed_message_arr
nonce = "$nonce"
pub_key_x = $pub_key_x_arr
pub_key_y = $pub_key_y_arr
signature = $signature_arr
EOF

echo "✅ Wrote $output_file"
