# LoRaWAN Packet Decoder

Web-based tool for decoding and analyzing **LoRaWAN 1.0.x** packets.  
Currently supports **Confirmed and Unconfirmed uplink/downlink packets** only.  

## Features

- Parse LoRaWAN 1.0.x packets (ConfUp, ConfDown, UnconfUp, UnconfDown)  
- Decrypt FRMPayload using NwkSKey
- Verify MIC (Message Integrity Code)  
- Handle FCnt context for frame counter rollover   

### TODO / Future plans
 
- [ ] Support JoinRequest / JoinAccept for 1.0.x
- [ ] Support LoRaWAN 1.1 packets (ConfUp, ConfDown, UnconfUp, UnconfDown)  
- [ ] Support RejoinRequest / JoinAccept for 1.1  
- [ ] Decode MAC Commands on a separate page  
- [ ] Multi-language UI support (i18n)

## Usage

1. Open `index.html` in a modern browser.  
2. Enter packet data:
   - `Packet (HEX)` – raw LoRaWAN packet in hexadecimal  
   - `NwkSKey` – network session key (16 bytes)  
   - `AppSKey` – application session key (16 bytes)  
   - Optional `FCntUp` / `FCntDown` – device context for frame counter  
3. Click **Decode packet** to parse, verify, and decrypt.  
4. Click **Clear all** to reset inputs.  

## Technologies

- HTML, CSS, JavaScript (ES6)  
- [asmCrypto.js](https://github.com/asmcrypto/asmcrypto.js) – AES-CMAC & AES-CTR for payload encryption/decryption  
- Lightweight front-end with no server-side dependencies
