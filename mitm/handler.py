import base64
import json
import math
from pathlib import Path
import random
import shutil
import time
from typing import Any, Optional
import zlib
from mitmproxy.http import HTTPFlow
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util import Padding


class Handler:
    LOGS_FOLDER = Path(__file__).parent.parent / 'logs'
    NETFLIX_SIGN_KEYS = [
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm84o+RfF7KdJgbE6lggYAdUxOArfgCsGCq33+kwAK/Jmf3VnNo1NOGlRpLQUFAqYRqG29u4wl8fH0YCn0v8JNjrxPWP83Hf5Xdnh7dHHwHSMc0LxA2MyYlGzn3jOF5dG/3EUmUKPEjK/SKnxeKfNRKBWnm0K1rzCmMUpiZz1pxgEB/cIJow6FrDAt2Djt4L1u6sJ/FOy/zA1Hf4mZhytgabDfapxAzsks+HF9rMr3wXW5lSP6y2lM+gjjX/bjqMLJQ6iqDi6++7ScBh0oNHmgUxsSFE3aBRBaCL1kz0HOYJe26UqJqMLQ71SwvjgM+KnxZvKa1ZHzQ+7vFTwE7+yxwIDAQAB',
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlibeiUhffUDs6QqZiB+jXH/MNgITf7OOcMzuSv4G3JysWkc0aPbT3vkCVaxdjNtw50zo2Si8I24z3/ggS3wZaF//lJ/jgA70siIL6J8kBt8zy3x+tup4Dc0QZH0k1oxzQxM90FB5x+UP0hORqQEUYZCGZ9RbZ/WNV70TAmFkjmckutWN9DtR6WUdAQWr0HxsxI9R05nz5qU2530AfQ95h+WGZqnRoG0W6xO1X05scyscNQg0PNCy3nfKBG+E6uIl5JB4dpc9cgSNgkfAIeuPURhpD0jHkJ/+4ytpdsXAGmwYmoJcCSE1TJyYYoExuoaE8gLFeM01xXK5VINU7/eWjQIDAQAB'
    ]

    def __init__(self) -> None:
        self.server_key: Optional[bytes] = None

        self.__proxy_sign_key = RSA.generate(2048, lambda x: bytes(random.getrandbits(8) for _ in range(x)))
        self.__proxy_rsa_key: Optional[RSA.RsaKey] = None
        self.__real_public_key: Optional[RSA.RsaKey] = None

        self.__loaded = False
        self.__disable_exchange = True

    def load(self):
        self.load_keys()
        self.init_logs()

        self.__loaded = True

    def load_keys(self) -> None:
        keys_path = Path(__file__).parent.parent / 'exchange_key.json'

        if keys_path.exists():
            data = json.loads(keys_path.read_bytes())
            self.server_key = base64.b64decode(data['server_key'])

            print('[+] Loaded keys!')
        else:
            print('[!] Decryption keys not found! Waiting for keys exchange ...')

    def init_logs(self):
        shutil.rmtree(Handler.LOGS_FOLDER, ignore_errors=True)
        Handler.LOGS_FOLDER.mkdir(parents=True, exist_ok=True)

        print('[+] Initialized session logs')

    def save_keys(self) -> None:
        keys_path = Path(__file__).parent.parent / 'exchange_key.json'

        keys_path.write_text(json.dumps({
            'server_key': base64.b64encode(self.server_key).decode('utf-8')
        }))

    def is_ready(self):
        return self.__loaded

    def on_send(self, flow: HTTPFlow) -> None:
        while not self.is_ready():
            time.sleep(1)

        if any(x in flow.request.pretty_url for x in [
            'msl_v1/cadmium', 'msl/cadmium', 'msl/playapi/cadmium'
        ]):
            # print('[+] Receive Netflix MSL request')

            chunks = json.loads(f'[{flow.request.content.decode("utf-8").replace("}{", "},{")}]')
            header = chunks[0]
            
            if not 'headerdata' in header:
                return
        
            headerdata = json.loads(base64.b64decode(header['headerdata']))
            
            if 'keyrequestdata' in headerdata:
                print('[+] Receive key exchange request for Netflix')

                if headerdata['keyrequestdata'][0]['scheme'] != 'ASYMMETRIC_WRAPPED' or headerdata['keyrequestdata'][0]['keydata']['mechanism'] != 'JWK_RSA':
                    print(f'{headerdata["keyrequestdata"][0]["scheme"]} key exchange scheme/mechanism not supported!')
                    return
                
                self.__real_public_key = RSA.import_key(base64.b64decode(headerdata['keyrequestdata'][0]['keydata']['publickey']))
                self.__proxy_rsa_key = RSA.generate(2048)
                
                print('[+] Change public key used for exchange to read server keys later')
                headerdata['keyrequestdata'][0]['keydata']['publickey'] = base64.b64encode(self.__proxy_rsa_key.public_key().export_key('DER')).decode('utf-8')

                header['headerdata'] = base64.b64encode(json.dumps(headerdata).encode('utf-8')).decode('utf-8')
                chunks[0] = header
                flow.request.content = ''.join([json.dumps(x) for x in chunks]).encode('utf-8')
                self.__disable_exchange = False

                print('[+] Send updated public key exchange to Netflix')

    def on_receive(self, flow: HTTPFlow) -> None:
        while not self.is_ready():
            time.sleep(1)
        
        if any(x in flow.request.pretty_url for x in [
            'msl_v1/cadmium', 'msl/cadmium', 'msl/playapi/cadmium'
        ]):
            # print('[+] Receive Netflix MSL response')

            chunks = json.loads(f'[{flow.response.content.decode("utf-8").replace("}{", "},{")}]')
            header = chunks[0]
            
            if not 'headerdata' in header:
                return
        
            headerdata = json.loads(base64.b64decode(header['headerdata']))

            if 'keyresponsedata' in headerdata:
                print('[+] Receive key exchange response from Netflix')

                if self.__disable_exchange:
                    print('[!] Key exchange update disabled! (probably du to previous errors)')
                    return
                
                decryptor = PKCS1_OAEP.new(self.__proxy_rsa_key)

                hmac_data = decryptor.decrypt(base64.b64decode(headerdata['keyresponsedata']['keydata']['hmackey']))
                encryption_data = decryptor.decrypt(base64.b64decode(headerdata['keyresponsedata']['keydata']['encryptionkey']))

                print('[+] Save MSL decryption key')
                self.server_key = Handler._b64_unpaded_decode(json.loads(encryption_data)['k'])
                
                encryptor = PKCS1_OAEP.new(self.__real_public_key)

                headerdata['keyresponsedata']['keydata']['hmackey'] = base64.b64encode(
                    encryptor.encrypt(hmac_data)
                ).decode('utf-8')

                headerdata['keyresponsedata']['keydata']['encryptionkey'] = base64.b64encode(
                    encryptor.encrypt(encryption_data)
                ).decode('utf-8')

                headerdata = json.dumps(headerdata).encode('utf-8')

                header['headerdata'] = base64.b64encode(headerdata).decode('utf-8')
                header['signature'] = base64.b64encode(pkcs1_15.new(self.__proxy_sign_key).sign(SHA256.new(headerdata))).decode('utf-8')

                chunks[0] = header
                flow.response.content = ''.join([json.dumps(x) for x in chunks]).encode('utf-8')

                print('[+] Saving keys')
                self.save_keys()

            elif 'ciphertext' in headerdata:
                if not self.server_key:
                    return
                
                # print('[+] New encrypted MSL request detected')
                
                req = self._parse_message(flow.request.content.decode('utf-8'))
                res = self._parse_message(flow.response.content.decode('utf-8'))

                request_id = ''.join([hex(zlib.crc32(x.encode('utf-8')))[2:] for x in [
                    flow.request.pretty_url, str(flow.request.timestamp_start), str(flow.request.timestamp_end)
                ]])

                log_path = Handler.LOGS_FOLDER / f'{request_id}.jsonc'

                with log_path.open('w+') as f:
                    f.write(f'''// Request ID: {request_id}
// URL: {flow.request.pretty_url}

// Sended:
{json.dumps(req, indent=4)}

// Recived:
{json.dumps(res, indent=4)}
''')

                print(f'[+] Saved decrypted MSL request to "{log_path.name}"')

        elif 'cadmium-playercore' in flow.request.pretty_url:
            print('[+] Update cadmium playercore file with our rsa proxy key')
            
            exported_key = base64.b64encode(self.__proxy_sign_key.public_key().export_key('DER'))

            for key in Handler.NETFLIX_SIGN_KEYS:
                flow.response.content = flow.response.content.replace(key.encode('utf-8'), exported_key)   

    def _parse_message(self, message: str) -> dict[str, Any]:
        payload_chunks: list[dict[str, Any]] = json.loads(f'[{message.replace("}{", "},{")}]')
        header = payload_chunks.pop(0)

        headerdata = json.loads(base64.b64decode(header['headerdata']))

        if 'ciphertext' in headerdata:
            decryptor = AES.new(key=self.server_key, mode=AES.MODE_CBC, iv=base64.b64decode(headerdata['iv']))
            headerdata = json.loads(Padding.unpad(decryptor.decrypt(base64.b64decode(headerdata['ciphertext'])), 16))

        message = {}

        if len(payload_chunks) > 0:
            raw = ''

            for payload_chunk in payload_chunks:
                payload = json.loads(base64.b64decode(
                    payload_chunk['payload']
                ).decode('utf-8'))

                decryptor = AES.new(self.server_key, AES.MODE_CBC, iv=base64.b64decode(payload['iv']))
                decrypted_content = json.loads(Padding.unpad(
                    decryptor.decrypt(base64.b64decode(payload['ciphertext'])), 16
                ).decode('utf-8'))

                content = base64.b64decode(decrypted_content['data'])

                if 'compressionalgo' in decrypted_content:
                    if decrypted_content['compressionalgo'] == 'GZIP':
                        content = zlib.decompress(content, 16 + zlib.MAX_WBITS)
                    elif decrypted_content['compressionalgo'] == 'LZW':
                        content = Handler._lzw_decompress(content)
                
                raw += content.decode('utf-8')

            message = json.loads(raw)

        return {
            'header': {
                **header,
                'headerdata': headerdata
            },
            'data': message
        }

    @staticmethod
    def _b64_unpaded_decode(payload: str) -> bytes:
        length = len(payload) % 4
        
        if length == 2:
            payload += '=='
        elif length == 3:
            payload += '='
        elif length != 0:
            raise ValueError('Invalid base64 string')

        return base64.urlsafe_b64decode(payload.encode('utf-8'))
    
    @staticmethod
    def _lzw_decompress(data: bytes) -> bytes:
        BYTE_SIZE = 8
        BYTE_RANGE = 256
        UNCOMPRESS_DICTIONARY = [[ui] for ui in range(0, BYTE_RANGE)]

        dictionary = UNCOMPRESS_DICTIONARY[:]
        codeIndex = 0
        codeOffset = 0
        bits = BYTE_SIZE
        uncompressed = [0 for i in range(0, math.ceil(len(data) * 1.5))]
        index = 0
        nextIndex = 0
        prevValue = []

        while codeIndex < len(data):
            bitsAvailable = (len(data) - codeIndex) * BYTE_SIZE - codeOffset
            if bitsAvailable < bits:
                break

            code = 0
            bitsDecoded = 0
            while bitsDecoded < bits:
                bitlen = min(bits - bitsDecoded, BYTE_SIZE - codeOffset)
                msbits = data[codeIndex]

                msbits <<= codeOffset
                msbits &= 0xff
                msbits >>= BYTE_SIZE - bitlen

                bitsDecoded += bitlen
                codeOffset += bitlen
                if codeOffset == BYTE_SIZE:
                    codeOffset = 0
                    codeIndex += 1

                code |= (msbits & 0xff) << (bits - bitsDecoded)

            value = None if code >= len(dictionary) else dictionary[code]
            if len(prevValue) == 0:
                bits += 1
            else:
                if not value:
                    prevValue.append(prevValue[0])
                else:
                    prevValue.append(value[0])

                dictionary.append(prevValue)
                prevValue = []

                if len(dictionary) == (1 << bits):
                    bits += 1

                if not value:
                    value = dictionary[code]

            nextIndex = index + len(value)

            if nextIndex >= len(uncompressed):
                increase = math.ceil(nextIndex * 1.5) - len(uncompressed)
                uncompressed.extend([0] * increase)

            uncompressed[index:index] = value
            index = nextIndex

            prevValue = prevValue + value

        return bytes(uncompressed[0:index])