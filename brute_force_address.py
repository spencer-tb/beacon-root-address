import hashlib
import random
from concurrent.futures import ThreadPoolExecutor

from eth_keys import keys

NUM_ZEROS = 6
NUM_THREADS = 4


def sign_and_generate_message():
    private_key = keys.PrivateKey(bytearray(random.getrandbits(8) for _ in range(32)))
    msg = b"Sample message for signing"
    msg_hash = hashlib.sha256(msg).digest()
    signature = private_key.sign_msg_hash(msg_hash)
    return msg_hash, signature.v, signature.r, signature.s


def recover_address_from_signature(msg_hash, v, r, s):
    signature = keys.Signature(vrs=(v, r, s))
    public_key = signature.recover_public_key_from_msg_hash(msg_hash)
    return public_key.to_checksum_address()


def generate_address_with_conditions(thread_id, output_file, special_file):
    iterations = 0
    while True:
        try:
            msg_hash, v, r, s = sign_and_generate_message()
            recovered_address = recover_address_from_signature(msg_hash, v, r, s)
        except Exception as e:
            print(f"Thread-{thread_id} | Error: {e}")
            continue

        if len(recovered_address[2:]) - len(recovered_address[2:].lstrip("0")) >= NUM_ZEROS:
            with open(output_file, "a") as f_out:
                f_out.write(
                    f"Thread-{thread_id} | Recovered Address: {recovered_address}, Msg Hash: {msg_hash.hex()}, v: {v}, r: {r.to_bytes(32, byteorder='big').hex()}, s: {s.to_bytes(32, byteorder='big').hex()}\n"
                )
                print(f"Thread-{thread_id} | Special Recovered Address: {recovered_address}")

            if "beac" in recovered_address[2:].lower():
                with open(special_file, "a") as f_special:
                    f_special.write(
                        f"Thread-{thread_id} | Special Recovered Address: {recovered_address}, Msg Hash: {msg_hash.hex()}, v: {v}, r: {r.to_bytes(32, byteorder='big').hex()}, s: {s.to_bytes(32, byteorder='big').hex()}\n"
                    )
                    print(f"Thread-{thread_id} | Special Recovered Address: {recovered_address}")

        iterations += 1
        if iterations % 1000 == 0:
            print(f"Thread-{thread_id} Iterations: {iterations}")


if __name__ == "__main__":
    output_file = "recovered_addresses.txt"
    special_file = "special_recovered_addresses.txt"

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        for i in range(NUM_THREADS):
            executor.submit(generate_address_with_conditions, i, output_file, special_file)
