# LoRaWAN Packet Decoder

Web-based tool for decoding and analyzing **LoRaWAN** packets.  
Supports both **LoRaWAN 1.0.x** and **LoRaWAN 1.1** specifications.

## Features

### LoRaWAN 1.0.x Support
- Parse Data packets (Unconfirmed/Confirmed Up/Down)
- Parse JoinRequest packets
- Parse and decrypt JoinAccept packets
- Decrypt FRMPayload
- Verify MIC (Message Integrity Code)
- Handle FCnt context for frame counter rollover

### LoRaWAN 1.1 Support
-  Parse Data packets (Unconfirmed/Confirmed Up/Down)
- Decrypt FRMPayload with proper key selection:
- Decrypt FOpts (MAC commands in header):
  - Legacy mode (original specification)
  - Errata mode (corrected specification)
- Verify MIC
- Support for advanced context:
  - FCntUp, AFCntDown, NFCntDown
  - ConfFCnt (for ACK packets)
  - TxDR, TxCH (for uplink MIC)

## Live Demo

The decoder is hosted online via **GitHub Pages**:  
**https://reflexios.github.io/lorawan-packet-parser**

## Usage

### Getting Started

1. Open `index.html` in a modern browser
2. Select LoRaWAN version (1.0.x or 1.1)
3. Enter packet data and keys
4. Click **Decode packet**

### LoRaWAN 1.0.x

**Required fields:**
- `Packet (HEX)` – raw LoRaWAN packet in hexadecimal

**Keys (depending on packet type):**
- `AppKey` – for JoinRequest/JoinAccept (16 bytes hex)
- `NwkSKey` – for Data packet MIC verification (16 bytes hex)
- `AppSKey` – for FRMPayload decryption (16 bytes hex)

**Optional context:**
- `FCntUp` – uplink frame counter (32-bit)
- `FCntDown` – downlink frame counter (32-bit)

### LoRaWAN 1.1

**Required fields:**
- `Packet (HEX)` – raw LoRaWAN packet in hexadecimal

**Keys:**
- `AppKey` – for Join procedures (16 bytes hex)
- `NwkKey` – for Join procedures (16 bytes hex)
- `FNwkSIntKey` – for uplink MIC (16 bytes hex)
- `SNwkSIntKey` – for MIC (16 bytes hex)
- `NwkSEncKey` – for FOpts/MAC commands encryption (16 bytes hex)
- `AppSKey` – for application payload (16 bytes hex)

**Optional context:**
- `FCntUp` – uplink frame counter (32-bit)
- `AFCntDown` – application downlink counter (32-bit)
- `NFCntDown` – network downlink counter (32-bit)
- `ConfFCnt` – confirmed packet counter (for ACK=1 packets)
- `TxDR` – TX data rate (for uplink MIC)
- `TxCH` – TX channel (for uplink MIC)

**Options:**
- `Use Errata-corrected FOpts encryption` – enable for corrected FOpts decryption

## Example Packets

### LoRaWAN 1.0.x Data Packet
```
Packet: 40F17DBE4900020001954378762B11FF0D
NwkSKey: 44024241ed4ce9a68c6a8bc055233fd3
AppSKey: ec925802ae430ca77fd3dd73cb2cc588
```

### LoRaWAN 1.0.x JoinRequest
```
Packet: 0031316973616765760C69376F35383434A05BBEDCC96C
AppKey: 0F37650C000000000F37650C0A5C164D
```

### LoRaWAN 1.0.x JoinAccept
```
Packet: 20CB9B8538C4B2656C0BEF370E11E6F2737E216F40915BA4EEC5795E3BD9D843CB
AppKey: 7F375E18000000007F375E181D5A1951
```

## Technologies

- **HTML, CSS, JavaScript (ES6)** – modern web standards
- **[asmCrypto.js](https://github.com/asmcrypto/asmcrypto.js)** – AES-CMAC, AES-CTR, AES-ECB implementations
- **No server-side dependencies** – runs entirely in the browser

## Development Roadmap

### Completed ✅
- [x] LoRaWAN 1.0.x Data packets (Unconf/Conf Up/Down)
- [x] JoinRequest/JoinAccept for 1.0.x
- [x] MIC verification for 1.0.x
- [x] Payload decryption for 1.0.x
- [x] LoRaWAN 1.1 Data packets (Unconf/Conf Up/Down)
- [x] MIC verification for 1.1
- [x] Payload decryption for 1.1
- [x] FOpts decryption for 1.1 (Legacy + Errata modes)

### Planned 🚧
- [ ] JoinRequest/JoinAccept for 1.1
- [ ] RejoinRequest support for 1.1
- [ ] MAC Commands decoder (separate page/modal)
- [ ] Custom payload decoder functions (JavaScript)
- [ ] Multi-language UI
- [ ] Export decoded data (JSON, CSV)

## References

- [LoRaWAN 1.0.4 Specification](https://lora-alliance.org/resource_hub/lorawan-specification-v1-0-4/)
- [LoRaWAN 1.1 Specification](https://lora-alliance.org/resource_hub/lorawan-specification-v1-1/)
- [LoRaWAN Backend Interfaces](https://lora-alliance.org/resource_hub/lorawan-backend-interfaces-v1-0/)
- [FOpts errata](https://resources.lora-alliance.org/technical-specifications/fopts-encryption-usage-of-fcntdwn-errata-on-the-lorawan-l2-1-1-specification/)
