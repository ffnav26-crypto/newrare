
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from protobuf_decoder.protobuf_decoder import Parser
import codecs
import time
from datetime import datetime
from colorama import Fore, Style
import urllib3
import os
import sys
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
# Disable only the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
red = Fore.RED
lg = Fore.LIGHTGREEN_EX
green = Fore.GREEN
bold = Style.BRIGHT
purple = Fore.MAGENTA
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)


REGION_LANG = {
            "ME": "ar",
            "IND": "hi",
            "ID": "id",
            "VN": "vi",
            "TH": "th",
            "BD": "bn",
            "PK": "ur",
            "TW": "zh",
            "EU": "en",
            "CIS": "ru",
            "NA": "en",
            "SAC": "es",
            "BR": "pt"
        }
REGION_URLS = {
            "IND": "https://client.ind.freefiremobile.com",
            "ID": "https://clientbp.ggblueshark.com/",
            "BR": "https://client.us.freefiremobile.com/",
            "ME": "https://clientbp.common.ggbluefox.com/",
            "VN": "https://clientbp.ggblueshark.com/",
            "TH": "https://clientbp.common.ggbluefox.com/",
            "CIS": "https://clientbp.ggblueshark.com/",
            "BD": "https://clientbp.ggblueshark.com/",
            "PK": "https://clientbp.ggblueshark.com/",
            "SG": "https://clientbp.ggblueshark.com/",
            "NA": "https://client.us.freefiremobile.com/",
            "SAC": "https://client.us.freefiremobile.com/",
            "EU": "https://clientbp.ggblueshark.com/",
            "TW": "https://clientbp.ggblueshark.com/"
        }

# Global counters with thread locks
progress_lock = threading.Lock()
success_count = 0
failed_count = 0
retry_count = 0


def get_region(language_code: str) -> str:
    return REGION_LANG.get(language_code)


def get_region_url(region_code: str) -> str:
    """Return URL for a given region code"""
    return REGION_URLS.get(region_code, None)


def EnC_Vr(N):
    if N < 0: ''
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)


def DEc_Uid(H):
    n = s = 0
    for b in bytes.fromhex(H):
        n |= (b & 0x7F) << s
        if not b & 0x80: break
        s += 7
    return n


def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)


def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value


def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet


def E_AEs(Pc):
    Z = bytes.fromhex(Pc)
    key = bytes(
        [89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes(
        [54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    K = AES.new(key, AES.MODE_CBC, iv)
    R = K.encrypt(pad(Z, AES.block_size))
    return bytes.fromhex(R.hex())


def generate_random_name(prefix, region):
    # Calculate available space for random part
    # Format: prefix-region-random (with hyphens = 2 chars)
    # Max total = 12 chars
    used_chars = len(prefix) + len(region) + 2  # +2 for the two hyphens
    random_length = 12 - used_chars

    if random_length < 1:
        random_length = 1  # Ensure at least 1 random character

    characters = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(random_length)).lower()
    name = f"{prefix}-{region}-{random_part}"
    return name


def generate_custom_password(random_length=9):
    characters = string.ascii_letters + string.digits
    random_part = ''.join(
        random.choice(characters) for _ in range(random_length)).upper()
    return f"NavOp-{random_part}-URMINE"


def create_acc(region, name_prefix):
    password = generate_custom_password()
    data = f"password={password}&client_type=2&source=2&app_id=100067"
    message = data.encode('utf-8')
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()

    url = "https://100067.connect.garena.com/oauth/guest/register"

    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        "Authorization": "Signature " + signature,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }

    response = requests.post(url, headers=headers, data=data)
    try:
        uid = response.json()['uid']
        return token(uid, password, region, name_prefix)
    except Exception as e:
        return create_acc(region, name_prefix)


def token(uid, password, region, name_prefix):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"

    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
    }

    body = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": key,
        "client_id": "100067"
    }

    response = requests.post(url, headers=headers, data=body)
    open_id = response.json()['open_id']
    access_token = response.json()["access_token"]
    refresh_token = response.json()['refresh_token']

    result = encode_string(open_id)
    field = to_unicode_escaped(result['field_14'])
    field = codecs.decode(field, 'unicode_escape').encode('latin1')
    return Major_Regsiter(access_token, open_id, field, uid, password, region, name_prefix)


def encode_string(original):
    keystream = [
        0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31,
        0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30
    ]
    encoded = ""
    for i in range(len(original)):
        orig_byte = ord(original[i])
        key_byte = keystream[i % len(keystream)]
        result_byte = orig_byte ^ key_byte
        encoded += chr(result_byte)
    return {"open_id": original, "field_14": encoded}


def to_unicode_escaped(s):
    """Convert string to Python-style Unicode escaped string"""
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)


def Major_Regsiter(access_token, open_id, field, uid, password, region, name_prefix):
    url = "https://loginbp.ggblueshark.com/MajorRegister"
    name = generate_random_name(name_prefix, region)

    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com",
        "ReleaseVersion": "OB50",
        "User-Agent":
        "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4."
    }

    payload = {
        1: name,
        2: access_token,
        3: open_id,
        5: 102000007,
        6: 4,
        7: 1,
        13: 1,
        14: field,
        15: "en",
        16: 1,
        17: 1
    }

    payload = CrEaTe_ProTo(payload).hex()
    payload = E_AEs(payload).hex()
    body = bytes.fromhex(payload)
    proxies = {
        "http": "socks4://",
        "https": "socks4://",
    }

    response = requests.post(url, headers=headers, data=body, verify=False)
    return login(uid, password, access_token, open_id, response.content.hex(),
                 response.status_code, name, region)


def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes(
        [89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes(
        [54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()


def chooseregion(data_bytes, jwt_token):
    url = "https://loginbp.ggblueshark.com/ChooseRegion"
    payload = data_bytes
    headers = {
        'User-Agent':
        "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'Authorization': f"Bearer {jwt_token}",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    response = requests.post(url, data=payload, headers=headers, verify=False)
    return response.status_code


def login(uid, password, access_token, open_id, response, status_code, name,
          region):

    lang = get_region(region)
    lang_b = lang.encode("ascii")
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com",
        "ReleaseVersion": "OB50",
        "User-Agent":
        "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }

    payload = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_b + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    data = payload
    data = data.replace(
        'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390'.
        encode(), access_token.encode())
    data = data.replace('1d8ec0240ede109973f3321b9354b44d'.encode(),
                        open_id.encode())
    d = encrypt_api(data.hex())

    Final_Payload = bytes.fromhex(d)
    if region.lower() == "me":
        URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
    else:
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
    RESPONSE = requests.post(URL,
                             headers=headers,
                             data=Final_Payload,
                             verify=False)

    if RESPONSE.status_code == 200:
        if len(RESPONSE.text) < 10:
            return False
        if lang.lower() not in ["ar", "en"]:
            json_result = get_available_room(RESPONSE.content.hex())
            parsed_data = json.loads(json_result)

            BASE64_TOKEN = parsed_data['8']['data']

            if region.lower() == "cis":
                region = "RU"
            fields = {1: region}

            fields = bytes.fromhex(encrypt_api(CrEaTe_ProTo(fields).hex()))
            r = chooseregion(fields, BASE64_TOKEN)

            if r == 200:
                return login_server(uid, password, access_token, open_id,
                                    response, status_code, name, region)

        else:
            BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find(
                "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        dat = GET_PAYLOAD_BY_DATA(BASE64_TOKEN, access_token, 1, response,
                                  status_code, name, uid, password, region)
        return dat


def login_server(uid, password, access_token, open_id, response, status_code,
                 name, region):
    lang = get_region(region)
    lang_b = lang.encode("ascii")

    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com",
        "ReleaseVersion": "OB50",
        "User-Agent":
        "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }

    payload = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_b + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    data = payload
    data = data.replace(
        'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390'.
        encode(), access_token.encode())
    data = data.replace('1d8ec0240ede109973f3321b9354b44d'.encode(),
                        open_id.encode())
    d = encrypt_api(data.hex())

    Final_Payload = bytes.fromhex(d)
    if region.lower == "me":
        URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
    else:
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
    RESPONSE = requests.post(URL,
                             headers=headers,
                             data=Final_Payload,
                             verify=False)

    if RESPONSE.status_code == 200:
        if len(RESPONSE.text) < 10:
            return False

        json_result = get_available_room(RESPONSE.content.hex())
        parsed_data = json.loads(json_result)

        BASE64_TOKEN = parsed_data['8']['data']

        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        dat = GET_PAYLOAD_BY_DATA(BASE64_TOKEN, access_token, 1, response,
                                  status_code, name, uid, password, region)
        return dat


import base64


def is_rare_uid(uid_str):
    """Check if UID has rare patterns (repeating/sequential digits)"""
    uid_str = str(uid_str)
    
    # Check for repeating digits (at least 3 in a row)
    for i in range(len(uid_str) - 2):
        if uid_str[i] == uid_str[i+1] == uid_str[i+2]:
            return True
    
    # Check for sequential digits (at least 4 in a row)
    for i in range(len(uid_str) - 3):
        try:
            digits = [int(uid_str[i+j]) for j in range(4)]
            # Ascending sequence
            if all(digits[j+1] - digits[j] == 1 for j in range(3)):
                return True
            # Descending sequence
            if all(digits[j] - digits[j+1] == 1 for j in range(3)):
                return True
        except:
            continue
    
    return False


def get_actual_account_id(uid, password):
    """Fetch actual account ID from JWT API"""
    try:
        url = f"https://jwt-api-delta.vercel.app/token?uid={uid}&password={password}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return data.get('accountId')
    except Exception as e:
        print(f"Error fetching account ID: {e}")
    return None


def GET_PAYLOAD_BY_DATA(JWT_TOKEN, NEW_ACCESS_TOKEN, date, response,
                        status_code, name, uid, password, region):
    try:
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(
            token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now = str(now)[:len(str(now)) - 7]
        formatted_time = date
        PAYLOAD = b':\x071.111.2\xaa\x01\x02ar\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014'
        PAYLOAD = PAYLOAD.replace(b"2023-12-24 04:21:34", str(now).encode())
        PAYLOAD = PAYLOAD.replace(
            b"15f5ba1de5234a2e73cc65b6f34ce4b299db1af616dd1dd8a6f31b147230e5b6",
            NEW_ACCESS_TOKEN.encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"4666ecda0003f1809655a7a8698573d0",
                                  NEW_EXTERNAL_ID.encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"7428b253defc164018c604a1ebbfebdf",
                                  SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = PAYLOAD.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        data = GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD, region)
        
        # Get actual account ID from JWT API
        account_id = get_actual_account_id(uid, password)
        
        return {
            "data": data,
            "response": response,
            "status_code": status_code,
            "name": name,
            "uid": uid,
            "password": password,
            "account_id": account_id,
            "is_rare": is_rare_uid(account_id) if account_id else False
        }
    except Exception as e:
        return None


def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict


def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        return None


def GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD, region):
    if region.lower() == "me":
        url = 'https://clientbp.ggblueshark.com/GetLoginData'
    else:
        link = get_region_url(region)
        url = f"{link}GetLoginData"

    headers = {
        'Expect': '100-continue',
        'Authorization': f'Bearer {JWT_TOKEN}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB50',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 10; G011A Build/PI)',
        'Host': 'clientbp.common.ggblueshark.com',
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate, br',
    }

    try:
        response = requests.post(url,
                                 headers=headers,
                                 data=PAYLOAD,
                                 verify=False,
                                 timeout=180)
        response.raise_for_status()
        x = response.content.hex()
        json_result = get_available_room(x)
        parsed_data = json.loads(json_result)

        return parsed_data

    except:
        return None


def worker_task(worker_id, region, total_accounts, file_lock, name_prefix, filename, start_time):
    """Worker function that creates accounts - all run in parallel independently"""
    global success_count, failed_count, retry_count

    max_retries = 100  # Increased for rare UID hunting
    retries = 0

    while retries < max_retries:
        # Check if we should continue
        with progress_lock:
            if success_count >= total_accounts:
                return  # Exit immediately

        try:
            r = create_acc(region, name_prefix)

            if r and r.get('status_code') == 200:
                uid = r["uid"]
                password = r["password"]
                name = r["name"]
                account_id = r.get("account_id")
                is_rare = r.get("is_rare", False)

                # Only count rare UIDs
                if not is_rare or not account_id:
                    retries += 1
                    print(f"{Fore.YELLOW}⏭️  Skipped non-rare UID: {account_id}{Fore.RESET}", flush=True)
                    continue

                # Reset retry counter on success
                retries = 0

                # Atomically increment and get current count
                with progress_lock:
                    if success_count >= total_accounts:
                        return  # Exit immediately if target already reached
                    success_count += 1
                    current = success_count

                # Get current timestamp for display only
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Write to file with lock in JSON format
                with file_lock:
                    # Read existing data
                    accounts_data = []
                    if os.path.exists(filename):
                        try:
                            with open(filename, 'r') as file:
                                accounts_data = json.load(file)
                        except (json.JSONDecodeError, FileNotFoundError):
                            accounts_data = []

                    # Add new account with account_id
                    accounts_data.append({
                        "accountId": account_id,
                        "password": password,
                        "uid": uid
                    })

                    # Write back to file
                    with open(filename, 'w') as file:
                        json.dump(accounts_data, file, indent=4)

                # Force flush to show instantly
                print(f"{lg}{bold}✅ RARE Account {current:02d}/{total_accounts} | AccountID: {account_id} | UID: {uid} | Pass: {password} | Time: {timestamp}{Fore.RESET}", flush=True)

                # Show instant completion message when target is reached
                if current == total_accounts:
                    end_time = time.time()
                    elapsed_time = end_time - start_time

                    minutes = int(elapsed_time // 60)
                    seconds = int(elapsed_time % 60)

                    print(f"\n{lg}{bold}{'='*60}{Fore.RESET}")
                    print(f"{lg}{bold}🎉 TARGET COMPLETED! All {total_accounts} RARE accounts created successfully!{Fore.RESET}")
                    print(f"{lg}{bold}⏱️  Total Time Taken: {minutes:02d}m {seconds:02d}s{Fore.RESET}")
                    print(f"{lg}{bold}📁 Saved to: {filename}{Fore.RESET}")
                    print(f"{lg}{bold}{'='*60}{Fore.RESET}\n", flush=True)
                    return  # Exit immediately after completion
                
                # Successfully created, exit this worker
                return
            else:
                # Failed to create account
                retries += 1
                with progress_lock:
                    if success_count >= total_accounts:
                        return  # Exit if target reached
                    retry_count += 1

        except Exception as e:
            # Check if target reached before retrying
            with progress_lock:
                if success_count >= total_accounts:
                    return  # Exit immediately
                retry_count += 1

            retries += 1
            continue


def main():
    global success_count, failed_count, retry_count

    print(
        f"""\n\n\n{Fore.RED+bold}  ▄████ ▓█████  ███▄    █ ▓█████  ██▀███   ▄▄▄      ▄▄▄█████▓ ▒█████   ██▀███  
         ██▒ ▀█▒▓█   ▀  ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒▒████▄    ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒
        ▒██░▄▄▄░▒███   ▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒▒██  ▀█▄  ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒
        ░▓█  ██▓▒▓█  ▄ ▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  ░██▄▄▄▄██ ░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  
        ░▒▓███▀▒░▒████▒▒██░   ▓██░░▒████▒░██▓ ▒██▒ ▓█   ▓██▒  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒
         ░▒   ▒ ░░ ▒░ ░░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░
          ░   ░  ░ ░  ░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░  ▒   ▒▒ ░    ░      ░ ▒ ▒░   ░▒ ░ ▒░
        ░ ░   ░    ░      ░   ░ ░    ░     ░░   ░   ░   ▒     ░      ░ ░ ░ ▒    ░░   ░ 
              ░    ░  ░         ░    ░  ░   ░           ░  ░             ░ ░     ░     \n                                           {Fore.RED}NAV X DEV{Fore.RESET}\n"""
    )

    # Auto-configured settings
    region = "IND"
    name_prefix = "NAV"
    total_accounts = 20

    print(f"{lg}{bold}🔧 AUTO CONFIGURATION:{Fore.RESET}")
    print(f"{lg}{bold}   • Region: {region}{Fore.RESET}")
    print(f"{lg}{bold}   • Name Prefix: {name_prefix}{Fore.RESET}")
    print(f"{lg}{bold}   • Total Accounts: {total_accounts}{Fore.RESET}\n")

    file_lock = threading.Lock()

    # Reset counters
    success_count = 0
    failed_count = 0
    retry_count = 0

    # Calculate cumulative filename
    existing_count = 0
    base_filename = f"{name_prefix} {region}.json"

    if os.path.exists(base_filename):
        try:
            with open(base_filename, 'r') as file:
                existing_data = json.load(file)
                existing_count = len(existing_data)
        except (json.JSONDecodeError, FileNotFoundError):
            existing_count = 0

    new_total = existing_count + total_accounts
    filename = f"{new_total} {name_prefix} {region}.json"

    if os.path.exists(base_filename) and existing_count > 0:
        try:
            with open(base_filename, 'r') as file:
                existing_data = json.load(file)
            with open(filename, 'w') as file:
                json.dump(existing_data, file, indent=4)
            os.remove(base_filename)
        except Exception as e:
            pass

    if existing_count > 0:
        print(f"{lg}{bold}📊 Existing accounts: {existing_count} | New total: {new_total}{Fore.RESET}")

    print(f"{lg}{bold}🚀 Creating all {total_accounts} accounts in parallel{Fore.RESET}")
    print(f"{lg}{bold}🔥 Maximum parallelization - all accounts running independently!{Fore.RESET}\n")

    overall_start_time = time.time()

    # Use maximum workers - create all accounts in parallel at once
    num_workers = total_accounts * 2  # 2 workers per account for redundancy

    print(f"{lg}{bold}⚡ Launching {num_workers} parallel workers...{Fore.RESET}\n")

    # Create thread pool and execute all workers at once
    executor = ThreadPoolExecutor(max_workers=num_workers)
    futures = []
    for worker_id in range(1, num_workers + 1):
        future = executor.submit(worker_task, worker_id, region, total_accounts, file_lock, name_prefix, filename, overall_start_time)
        futures.append(future)

    # Wait for all workers to complete
    for future in as_completed(futures):
        try:
            future.result(timeout=30)
        except Exception as e:
            pass

        # If we've reached target, cancel remaining futures
        with progress_lock:
            if success_count >= total_accounts:
                for remaining in futures:
                    remaining.cancel()
                break

    executor.shutdown(wait=True)

    # Calculate elapsed time
    end_time = time.time()
    elapsed_time = end_time - overall_start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)

    # Print final summary if not already printed
    with progress_lock:
        if success_count < total_accounts:
            print(f"\n{lg}{bold}{'='*60}{Fore.RESET}")
            print(f"{lg}{bold}📊 PROCESS COMPLETED{Fore.RESET}")
            print(f"{lg}{bold}{'='*60}{Fore.RESET}")
            print(f"{lg}{bold}✅ Accounts Created: {success_count}/{total_accounts}{Fore.RESET}")
            print(f"{lg}{bold}⏱️  Total Time: {minutes:02d}m {seconds:02d}s{Fore.RESET}")
            print(f"{lg}{bold}📁 Accounts saved to: {filename}{Fore.RESET}")
            print(f"{lg}{bold}{'='*60}{Fore.RESET}\n")


if __name__ == "__main__":
    main()
