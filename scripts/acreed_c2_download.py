import requests
import base64
import json
import os
import sys
import struct
import pefile
import yara
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

RULE_SOURCE = """
rule AmateraDecrypt
{
    meta:
        author = "YungBinary"
        description = "Find Amatera XOR key"
    strings:
        $decrypt_global = {
            A1 ?? ?? ?? ??                  // mov     eax, dword ptr ds:szXorKey ; "852149723"
            89 45 ??                        // mov     dword ptr [ebp+xor_key], eax
            8B 0D ?? ?? ?? ??               // mov     ecx, dword ptr ds:szXorKey+4 ; "49723"
            89 4D ??                        // mov     dword ptr [ebp+xor_key+4], ecx
            66 8B 15 ?? ?? ?? ??            // mov     dx, word ptr ds:szXorKey+8 ; "3"
            66 89 55 ??                     // mov     word ptr [ebp+xor_key+8], dx
            8D 45 ??                        // lea     eax, [ebp+xor_key]
            50                              // push    eax
            E8                              // call
        }
        $decrypt_stack = {
            83 EC 1C                        // sub     esp, 1Ch
            56                              // push    esi
            89 ?? ??                        // mov     [ebp+var], reg
            [0-50]                          // Skip variable checks present in new versions
            C6 45 ?? ??                     // mov     [ebp+char_1], imm
            C6 45 ?? ??                     // mov     [ebp+char_2], imm
            C6 45 ?? ??                     // mov     [ebp+char_3], imm
        }
    condition:
        uint16(0) == 0x5A4D and ($decrypt_global or $decrypt_stack)
}
"""

RULE_SOURCE_AES_KEY = """
rule AmateraAESKey
{
    meta:
        author = "YungBinary"
        description = "Find Amatera AES key"
    strings:
        $aes_key_on_stack = {
            83 EC 2C                        // sub     esp, 2Ch
            C6 45 D4 ??                     // mov     byte ptr [ebp-2Ch], ??
            C6 45 D5 ??                     // mov     byte ptr [ebp-2Bh], ??
            C6 45 D6 ??                     // mov     byte ptr [ebp-2Ah], ??
            C6 45 D7 ??                     // mov     byte ptr [ebp-29h], ??
            C6 45 D8 ??                     // mov     byte ptr [ebp-28h], ??
            C6 45 D9 ??                     // mov     byte ptr [ebp-27h], ??
            C6 45 DA ??                     // mov     byte ptr [ebp-26h], ??
            C6 45 DB ??                     // mov     byte ptr [ebp-25h], ??
            C6 45 DC ??                     // mov     byte ptr [ebp-24h], ??
            C6 45 DD ??                     // mov     byte ptr [ebp-23h], ??
            C6 45 DE ??                     // mov     byte ptr [ebp-22h], ??
            C6 45 DF ??                     // mov     byte ptr [ebp-21h], ??
            C6 45 E0 ??                     // mov     byte ptr [ebp-20h], ??
            C6 45 E1 ??                     // mov     byte ptr [ebp-1Fh], ??
            C6 45 E2 ??                     // mov     byte ptr [ebp-1Eh], ??
            C6 45 E3 ??                     // mov     byte ptr [ebp-1Dh], ??
            C6 45 E4 ??                     // mov     byte ptr [ebp-1Ch], ??
            C6 45 E5 ??                     // mov     byte ptr [ebp-1Bh], ??
            C6 45 E6 ??                     // mov     byte ptr [ebp-1Ah], ??
            C6 45 E7 ??                     // mov     byte ptr [ebp-19h], ??
            C6 45 E8 ??                     // mov     byte ptr [ebp-18h], ??
            C6 45 E9 ??                     // mov     byte ptr [ebp-17h], ??
            C6 45 EA ??                     // mov     byte ptr [ebp-16h], ??
            C6 45 EB ??                     // mov     byte ptr [ebp-15h], ??
            C6 45 EC ??                     // mov     byte ptr [ebp-14h], ??
            C6 45 ED ??                     // mov     byte ptr [ebp-13h], ??
            C6 45 EE ??                     // mov     byte ptr [ebp-12h], ??
            C6 45 EF ??                     // mov     byte ptr [ebp-11h], ??
            C6 45 F0 ??                     // mov     byte ptr [ebp-10h], ??
            C6 45 F1 ??                     // mov     byte ptr [ebp-0Fh], ??
            C6 45 F2 ??                     // mov     byte ptr [ebp-0Eh], ??
            C6 45 F3 ??                     // mov     byte ptr [ebp-0Dh], ??
            C7 45 F4 10 00 00 00            // mov     dword ptr [ebp-0Ch], 10h
        }
        $aes_key_global = {
            6A 20                           // push 32
            68 ?? ?? ?? ??                  // push offset key_blob
        }
    condition:
        uint16(0) == 0x5A4D and ($aes_key_on_stack or $aes_key_global)
}
"""

B64_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

# --- Binary Parser Functions ---

def yara_scan(raw_data: bytes, rule_source: str):
    """Scan binary data with a YARA rule and return the first match offset."""
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                return instance.offset
    return None


def xor_data(data, key):
    """XOR data with a repeating key."""
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(key[i % len(key)] ^ data[i])
    return decoded


def decode_and_decrypt(data_bytes, xor_key):
    """Decode base64 and XOR decrypt a string from the binary."""
    if not data_bytes:
        return ""

    clean_bytes = data_bytes.rstrip(b"\x00")

    # Heuristic: Check if valid Base64
    if any(b not in B64_CHARS for b in clean_bytes):
        return clean_bytes.decode("utf-8", errors="ignore")

    try:
        decoded = base64.b64decode(clean_bytes, validate=True)
        decrypted = xor_data(decoded, xor_key)
        # Heuristic: Check if result is printable ASCII
        if all(0x20 <= b <= 0x7E for b in decrypted if b != 0):
            return decrypted.decode("utf-8", errors="ignore").rstrip("\x00")
    except Exception:
        pass

    return clean_bytes.decode("utf-8", errors="ignore")


def extract_config(data):
    """Extract configuration from an Amatera Stealer binary."""
    config_dict = {}

    pe = pefile.PE(data=data)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    offset = yara_scan(data, RULE_SOURCE)
    if offset is None:
        print("[!] YARA scan for XOR key failed.")
        return config_dict

    key_str = b""
    if data[offset] == 0xA1:  # $decrypt_global
        key_str_va = struct.unpack("i", data[offset + 1 : offset + 5])[0]
        key_str = (
            pe.get_string_at_rva(key_str_va - image_base, max_length=20) + b"\x00"
        )

    elif data[offset] == 0x83:  # $decrypt_stack
        key_bytes = bytearray()
        # Skip sub/push/mov reg (7 bytes)
        scan_start = offset + 7
        current_idx = scan_start

        # Scan forward to find the start of the key construction (pattern: C6 45 ?? ?? C6 45)
        # This handles the gap introduced by conditional checks in newer versions.
        for i in range(64):
            idx = scan_start + i
            if idx + 6 > len(data): break
            if (data[idx] == 0xC6 and data[idx + 1] == 0x45 and
                data[idx + 4] == 0xC6 and data[idx + 5] == 0x45):
                current_idx = idx
                break

        for _ in range(32):
            if current_idx + 4 > len(data): break
            if data[current_idx] != 0xC6 or data[current_idx + 1] != 0x45:
                break
            val = data[current_idx + 3]
            if val == 0x00:
                break
            key_bytes.append(val)
            current_idx += 4
        key_str = key_bytes + b"\x00"

    if key_str:
        config_dict["xor_key"] = key_str.rstrip(b"\x00").decode(
            "utf-8", errors="ignore"
        )

    aes_key_offset = yara_scan(data, RULE_SOURCE_AES_KEY)
    if aes_key_offset:
        # Check match type based on the first instruction opcode
        if data[aes_key_offset] == 0x83:  # $aes_key_on_stack (sub esp, 2C)
            aes_key = bytearray()
            aes_block = data[aes_key_offset : aes_key_offset + 131]
            for i in range(0, len(aes_block) - 4, 4):
                aes_key.append(aes_block[i + 6])
            config_dict["cryptokey"] = aes_key.hex()
            config_dict["cryptokey_type"] = "AES"
        elif data[aes_key_offset] == 0x6A:  # $aes_key_global (push 32)
            # Format: 6A 20 68 [VA VA VA VA]
            key_va = struct.unpack("I", data[aes_key_offset + 3 : aes_key_offset + 7])[0]
            key_rva = key_va - image_base
            # Attempt to read the key (32 bytes) from the data section
            aes_key = pe.get_data(key_rva, 32)
            config_dict["cryptokey"] = aes_key.hex()
            config_dict["cryptokey_type"] = "AES"

    data_section = next(
        (
            s
            for s in pe.sections
            if s.Name.decode().strip("\x00").lower() == ".data"
        ),
        None,
    )
    if data_section:
        # First 16 bytes = 4 pointers
        pointers_raw = pe.get_data(data_section.VirtualAddress, 16)
        if len(pointers_raw) == 16:
            ptrs = struct.unpack("4I", pointers_raw)
            extracted = []

            for ptr in ptrs:
                rva = ptr - image_base
                if 0 < rva < pe.OPTIONAL_HEADER.SizeOfImage:
                    extracted.append(pe.get_string_at_rva(rva))
                else:
                    extracted.append(b"")

            if len(extracted) == 4:
                config_dict["payload_guid_1"] = decode_and_decrypt(
                    extracted[0], key_str
                )
                config_dict["payload_guid_2"] = decode_and_decrypt(
                    extracted[1], key_str
                )
                config_dict["fake_c2"] = decode_and_decrypt(extracted[2], key_str)

                real_c2 = decode_and_decrypt(extracted[3], key_str)
                config_dict["CNCs"] = [f"https://{real_c2}"]

    return config_dict


RESPONSE_DIR = "responses"
PAYLOAD_DIR = "payloads"

def save_to_file(directory, filename, data):
    """Saves data to a file in the specified directory."""
    filepath = os.path.join(directory, filename)
    mode = 'wb' if isinstance(data, bytes) else 'w'
    encoding = None if mode == 'wb' else 'utf-8'
    try:
        with open(filepath, mode, encoding=encoding) as f:
            f.write(data)
        print(f"    [+] Saved data to '{filepath}'")
    except Exception as e:
        print(f"    [!] Failed to save data to '{filepath}': {e}")

def encrypt_request(data_dict: dict, aes_key: bytes) -> bytes:
    """Encrypts the request body using AES-256-CBC."""
    plaintext = json.dumps(data_dict).encode('utf-8')
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_response(response_data: bytes, aes_key: bytes) -> bytes:
    """Decrypts the C2 response using AES-256-CBC."""
    if len(response_data) < 16:
        raise ValueError("Response data is too short to contain an IV.")
    iv = response_data[:16]
    ciphertext = response_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext
    except ValueError:
        return padded_plaintext

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypts data using a repeating XOR key."""
    return bytes(xor_data(data, key))

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_amatera_binary>")
        print("  Extracts C2 configuration from an Amatera Stealer binary and communicates with the C2 server.")
        sys.exit(1)

    binary_path = sys.argv[1]

    print(f"[*] Loading binary: {binary_path}")
    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()
    except Exception as e:
        print(f"[!] Failed to read binary file: {e}")
        sys.exit(1)

    print("[*] Extracting configuration from binary...")
    config = extract_config(binary_data)

    if not config:
        print("[!] Failed to extract configuration from binary. Is this an Amatera Stealer sample?")
        sys.exit(1)

    print("[+] Extracted configuration:")
    print(json.dumps(config, indent=4))

    required_fields = ["xor_key", "cryptokey", "CNCs", "payload_guid_1", "fake_c2"]
    missing = [f for f in required_fields if not config.get(f)]
    if missing:
        print(f"[!] Missing required config fields: {missing}")
        sys.exit(1)

    xor_key = config["xor_key"].encode("utf-8") + b"\x00"
    aes_key = bytes.fromhex(config["cryptokey"])
    c2_url = config["CNCs"][0]
    c2_domain = c2_url.replace("https://", "").replace("http://", "").rstrip("/")
    c2_host_header = config["fake_c2"]
    payload_guid = config["payload_guid_1"]

    print(f"\n[*] Using configuration:")
    print(f"    XOR Key: {config['xor_key']}")
    print(f"    AES Key: {config['cryptokey']}")
    print(f"    C2 Domain: {c2_domain}")
    print(f"    Host Header: {c2_host_header}")
    print(f"    Payload GUID: {payload_guid}")

    os.makedirs(RESPONSE_DIR, exist_ok=True)
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    print(f"\n[*] Saving all intermediate responses to the '{RESPONSE_DIR}/' directory.")

    c2_url_base = f"https://{c2_domain}/"
    headers = {
        "Content-Type": "application/octet-stream",
        "Connection": "close",
        "Host": c2_host_header
    }

    print("\n[*] STEP 1: Performing 'GetEndpoints' handshake...")
    get_endpoints_json = {"Command": "GetEndpoints"}
    encrypted_endpoints_body = encrypt_request(get_endpoints_json, aes_key)

    try:
        response_step1 = requests.post(c2_url_base, data=encrypted_endpoints_body, headers=headers, verify=False, timeout=10)
        response_step1.raise_for_status()
        print(f"[+] Received {len(response_step1.content)} bytes from C2.")
        save_to_file(RESPONSE_DIR, "step1_raw_encrypted_response.bin", response_step1.content)
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP Request for endpoints failed: {e}")
        return

    try:
        decrypted_endpoints_response = decrypt_response(response_step1.content, aes_key)
        endpoints_config = json.loads(decrypted_endpoints_response)
        print("[+] Decrypted endpoints configuration.")
        save_to_file(RESPONSE_DIR, "step1_decrypted_endpoints.json", json.dumps(endpoints_config, indent=4))

        payload_config_path = endpoints_config.get("c")
        if not payload_config_path:
            print("[!] Could not find the required path ('c' key) in the endpoints response.")
            return
        print(f"[*] Extracted payload config path: '{payload_config_path}'")

    except Exception as e:
        print(f"[!] Failed to process endpoints response: {e}")
        return

    print("\n[*] STEP 2: Fetching the main payload configuration...")
    get_payload_json = {"Id": payload_guid}
    encrypted_payload_body = encrypt_request(get_payload_json, aes_key)
    payload_config_url = f"https://{c2_domain}{payload_config_path}"

    try:
        response_step2 = requests.post(payload_config_url, data=encrypted_payload_body, headers=headers, verify=False, timeout=10)
        response_step2.raise_for_status()
        print(f"[+] Received {len(response_step2.content)} bytes from C2.")
        save_to_file(RESPONSE_DIR, "step2_raw_encrypted_response.bin", response_step2.content)
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP Request for payload config failed: {e}")
        return

    print("\n[*] STEP 3: Decrypting and processing final configuration...")
    try:
        decrypted_c2_response = decrypt_response(response_step2.content, aes_key)
        print("[+] AES decryption successful.")
        save_to_file(RESPONSE_DIR, "step3_1_aes_decrypted.b64", decrypted_c2_response)
    except Exception as e:
        print(f"[!] AES decryption failed: {e}")
        return

    try:
        base64_decoded_data = base64.b64decode(decrypted_c2_response)
        print(f"[+] Base64 decoding successful ({len(base64_decoded_data)} bytes).")
        save_to_file(RESPONSE_DIR, "step3_2_b64_decoded.bin", base64_decoded_data)
    except Exception as e:
        print(f"[!] Base64 decoding failed: {e}")
        return

    final_config_json_data = xor_decrypt(base64_decoded_data, xor_key)
    print("[+] XOR decryption successful.")
    save_to_file(RESPONSE_DIR, "step3_3_final_decrypted_config.bin", final_config_json_data)

    try:
        final_config = json.loads(final_config_json_data)
        save_to_file(RESPONSE_DIR, "final_config.json", json.dumps(final_config, indent=4))
        print("[+] Successfully parsed final configuration as JSON.")
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse final config as JSON: {e}")
        return

    if 'ld' in final_config and isinstance(final_config.get('ld'), list):
        print(f"\n[*] STEP 4: Found download jobs. Saving to '{PAYLOAD_DIR}/' directory...")
        for idx, job in enumerate(final_config.get('ld', [])):
            if 'u' in job:
                url = job.get('u')
                filename = os.path.basename(url.split('?')[0]) or f"payload_{idx+1}.bin"
                print(f"    -> Downloading from: {url}")
                try:
                    payload_response = requests.get(url, verify=False, timeout=15)
                    payload_response.raise_for_status()
                    # The analysis shows these payloads are used raw (no further decryption)
                    save_to_file(PAYLOAD_DIR, filename, payload_response.content)
                except requests.exceptions.RequestException as e:
                    print(f"    [!] Failed to download payload from {url}: {e}")
            else:
                print(f"    [!] Job {idx+1} is missing a URL ('u' key).")
    else:
        print("\n[*] No download jobs ('ld' key) found in the configuration.")

if __name__ == "__main__":
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    main()
