<p align="center">
    <img src="https://files.catbox.moe/djwpvn.png" height="21px" width="21px"> <a href="https://github.com/retouching/nf-msl-reader">Netflix MSL Reader</a>
    <br/>
    <sup><em>Intercept MSL requests and responses from Netflix</em></sup>
</p>

## Features

- :eye: Transparent MSL requests and responses interception
- :unlock: Decrypt content and return parsed data
- :scroll: Save logs data for let you analyse data later

## Prerequisites:

- [git](https://git-scm.com/)
- [mitmproxy](https://mitmproxy.org/)
- [Python (up to 3.12)](https://www.python.org/)
- [Poetry](https://python-poetry.org/docs/#installation)
- Any proxy browser extension (like [FoxyProxy](https://chromewebstore.google.com/detail/foxyproxy/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=fr))
- Valid premium Netflix account

> [!IMPORTANT]
> To intercept SSL requests and responses with mitmproxy, you need to install [mitmproxy certificate](https://docs.mitmproxy.org/stable/concepts-certificates/). 

## Installation

```shell
$ git clone https://github.com/retouching/nf-msl-reader.git
$ cd nf-msl-reader
$ poetry install
```

## Usage

> [!IMPORTANT]
> If you are logged already, you have to delete the netflix MSL session to force it to recreate the session. To do it:
> 
> - Go on Netflix
> - Open devtools (F12)
> - Go in Application > IndexedDB > netflix.player and click "Delete database"

1. Start **mitmproxy** with **script enabled**:
```shell
$ mitmdump -s run.py -q
```

2. Switch to **mitmproxy proxy** on proxy browser extension

3. Press `CTRL + F5` on Netflix and start navigating. **Clear cache is important beacause the script update cadmium playercore file**.

4. You can get **intercepted requests and responses** in logs folder.

If all is done, you have this on your terminal:

```
[!] Exchange keys not found! Waiting for keys exchange ...
[+] Initialized logs
[+] Update cadmium playercore file with our rsa proxy key
[+] Receive Netflix MSL request
[+] Receive key exchange request for Netflix
[+] Change public key used for exchange to read server keys later
[+] Send updated public key exchange to Netflix
[+] Receive Netflix MSL response
[+] Receive key exchange response from Netflix
[+] Save MSL keys
[+] Saved MSL request "xxx"
[+] Saving keys
[+] Receive Netflix MSL request
[+] Receive Netflix MSL response
[+] Saved MSL request "xxx"
```

## Examples

Log file:
```ts
{
    "url": string,
    "requested_at": number,
    "raw": {
        "request": any[],
        "response": any[]
    },
    "parsed": {
        "request": {
            "header": any,
            "data": any
        },
        "response": {
            "header": any,
            "data": any
        }
    }
}
```

---

> *README style taken from [devine](https://github.com/devine-dl/devine)*