// Supported packet types for LoRaWAN 1.0.x
const SUPPORTED_DATA_PACKETS = [0x40, 0x60, 0x80, 0xA0]; // Unconf/Conf Up/Down
const PROPRIETARY_PACKET = 0xE0;
const JOIN_REQUEST_PACKET = 0x00;
const JOIN_ACCEPT_PACKET = 0x20;
const REJOIN_REQUEST_PACKET = 0xC0;

window.parseLoRaWANPacket = function (bytes, appKeyHex) {
  if (bytes.length < 12) {
    throw new Error(I18N.t("errors.packetTooShort", { len: bytes.length }));
  }

  const mhdr = bytes[0];
  const mtype = mhdr & 0xe0;

  // Check for Proprietary packets - cannot process
  if (mtype === PROPRIETARY_PACKET) {
    throw new Error(I18N.t("errors.proprietaryPacket"));
  }

  // Parse data packet (Unconfirmed/Confirmed Up/Down)
  if (SUPPORTED_DATA_PACKETS.includes(mtype)) {
      return parseDataPacket(bytes);
  }

  // Parse JoinRequest packet
  if (mtype === JOIN_REQUEST_PACKET) {
    return parseJoinRequest(bytes);
  }

  // Parse JoinAccept packet
  if (mtype === JOIN_ACCEPT_PACKET) {
    return parseJoinAccept(bytes, appKeyHex);
  }

  throw new Error(I18N.t("errors.unsupportedPacketType", { type: MTYPE[mtype] || 'Unknown' }));
};

function parseJoinAccept(bytes, appKeyHex) {
  // JoinAccept structure: MHDR (1) + Encrypted[JoinNonce (3) + NetId (3) + DevAddr (4) + DLSettings(1) + RxDelay (1) + CFlist(16, optional) + MIC (4)] = 17/33 bytes
  if (bytes.length !== 17 && bytes.length !== 33) {
    throw new Error(I18N.t("errors.joinAcceptLength", { len: bytes.length }));
  }

  if (!appKeyHex || appKeyHex.trim() === "") {
    throw new Error(I18N.t("errors.required", { name: "AppKey" }));
  }

  const packet = {};

  const mhdr = bytes[0];
  packet.MHDR = mhdr;
  packet.MType = mhdr & 0xe0;
  packet.MTypeStr = MTYPE[packet.MType];
  packet.Major = mhdr & 0x03;

  // Decrypt everything after MHDR (including MIC)
  const encryptedPart = new Uint8Array(bytes.slice(1));
  const appKey = new Uint8Array(hexToBytes(appKeyHex));
  const decryptedPart = decryptJoinAccept(appKey, encryptedPart);

  let offset = 0;

  packet.decryptedPayload = decryptedPart;

  // JoinNonce (3 bytes in LE)
  const joinNonceBytes = decryptedPart.slice(offset, offset + 3);
  offset += 3;
  packet.JoinNonceBytes = joinNonceBytes;
  packet.JoinNonce = bytesToInt(joinNonceBytes);

  // NetID (3 bytes in LE)
  const netIdBytes = decryptedPart.slice(offset, offset + 3);
  offset += 3;
  packet.NetIdBytes = netIdBytes;
  packet.NetId = bytesToInt(netIdBytes);

  // DevAddr (4 bytes in LE, display in BE)
  const devAddrLE = decryptedPart.slice(offset, offset + 4);
  offset += 4;
  packet.DevAddrLE = devAddrLE;
  packet.DevAddr = reverseBytes(devAddrLE);
  packet.DevAddrHex = bytesToHex(packet.DevAddr);

  // DLSettings (1 byte)
  const dlsettings = decryptedPart[offset++];
  packet.DLSettings = dlsettings;
  packet.RX2DataRate = dlsettings & 0x0F;
  packet.RX1DROffset = (dlsettings >> 4) & 0x07;

  // RxDelay (1 byte)
  packet.RxDelay = decryptedPart[offset++];

  // CFList (16 bytes, optional)
  if (decryptedPart.length > offset + 4) { // Has CFList before MIC
    const cflist = decryptedPart.slice(offset, offset + 16);
    const cfType = cflist[15];

    packet.CFList = {};

    if (cfType === 0) {
      // Frequencies (5 x 3 bytes each)
      packet.CFList.Type = 'Frequencies';
      packet.CFList.Frequencies = [];
      for (let i = 0; i < 15; i += 3) {
        const freqBytes = cflist.slice(i, i + 3);
        const freq = bytesToInt(freqBytes) * 100; // Frequency in Hz (multiply by 100)
        if (freq > 0) {
          packet.CFList.Frequencies.push(freq);
        }
      }
    } else {
      // ChMasks (6 x 2 bytes each)
      packet.CFList.Type = 'ChMasks';
      packet.CFList.ChMasks = [];
      for (let i = 0; i < 12; i += 2) {
        const value = (cflist[i + 1] << 8) | cflist[i];
        const binary = value.toString(2).padStart(16, '0');
        packet.CFList.ChMasks.push(binary);
      }
    }

    offset += 16;
  }

  // MIC (4 bytes)
  packet.MIC = decryptedPart.slice(offset, offset + 4);
  packet.MICHex = bytesToHex(packet.MIC);

  return packet;
}

function parseJoinRequest(bytes) {
  // JoinRequest structure: MHDR (1) + JoinEUI (8) + DevEUI (8) + DevNonce (2) + MIC (4) = 23 bytes
  if (bytes.length !== 23) {
    throw new Error(I18N.t("errors.joinRequestLength", { len: bytes.length }));
  }

  const packet = {};
  let offset = 0;

  const mhdr = bytes[offset++];
  packet.MHDR = mhdr;
  packet.MType = mhdr & 0xe0;
  packet.MTypeStr = MTYPE[packet.MType];
  packet.Major = mhdr & 0x03;

  // JoinEUI (8 bytes in LE, display in BE)
  const joinEuiLE = bytes.slice(offset, offset + 8);
  offset += 8;
  packet.JoinEuiLE = joinEuiLE;
  packet.JoinEui = reverseBytes(joinEuiLE);
  packet.JoinEuiHex = bytesToHex(packet.JoinEui);

  // DevEUI (8 bytes in LE, display in BE)
  const devEuiLE = bytes.slice(offset, offset + 8);
  offset += 8;
  packet.DevEuiLE = devEuiLE;
  packet.DevEui = reverseBytes(devEuiLE);
  packet.DevEuiHex = bytesToHex(packet.DevEui);

  // DevNonce (2 bytes in LE)
  const devNonceBytes = bytes.slice(offset, offset + 2);
  offset += 2;
  packet.DevNonceBytes = devNonceBytes;
  packet.DevNonce = bytesToInt(devNonceBytes);

  // MIC (4 bytes)
  packet.MIC = bytes.slice(offset, offset + 4);
  packet.MICHex = bytesToHex(packet.MIC);

  return packet;
}

function parseDataPacket(bytes) {
  const packet = {};
  let offset = 0;

  const mhdr = bytes[offset++];
  packet.MHDR = mhdr;
  packet.MType = mhdr & 0xe0;
  packet.MTypeStr = MTYPE[packet.MType];
  packet.Major = mhdr & 0x03;

  if (!packet.MTypeStr) {
    throw new Error(
      I18N.t("errors.unknownMType", {
        value: `0x${packet.MType.toString(16).padStart(2, "0")}`,
      }),
    );
  }

  packet.Direction =
    packet.MType === 0x40 || packet.MType === 0x80 ? "up" : "down";

  const devAddrLE = bytes.slice(offset, offset + 4);
  offset += 4;
  packet.DevAddrLE = devAddrLE;
  packet.DevAddr = reverseBytes(devAddrLE);
  packet.DevAddrHex = bytesToHex(packet.DevAddr);

  const fctrl = bytes[offset++];
  packet.FCtrl = fctrl;
  packet.FOptsLen = fctrl & 0x0f;

  if (packet.Direction === "up") {
    packet.ADR = !!(fctrl & FCTRL_UP.ADR);
    packet.ADRACKReq = !!(fctrl & FCTRL_UP.ADRACKReq);
    packet.ACK = !!(fctrl & FCTRL_UP.ACK);
    packet.ClassB = !!(fctrl & FCTRL_UP.ClassB);
  } else {
    packet.ADR = !!(fctrl & FCTRL_DOWN.ADR);
    packet.ACK = !!(fctrl & FCTRL_DOWN.ACK);
    packet.FPending = !!(fctrl & FCTRL_DOWN.FPending);
  }

  packet.FCntBytes = bytes.slice(offset, offset + 2);
  packet.FCnt = bytesToInt(packet.FCntBytes);
  offset += 2;

  if (packet.FOptsLen > 15) {
    throw new Error(I18N.t("errors.fOptsLenTooBig", { len: packet.FOptsLen }));
  }

  packet.FOpts = bytes.slice(offset, offset + packet.FOptsLen);
  packet.FOptsHex = bytesToHex(packet.FOpts);
  offset += packet.FOptsLen;

  const remaining = bytes.length - offset;

  if (remaining > 4) {
    packet.FPort = bytes[offset++];
    packet.FRMPayload = bytes.slice(offset, -4);
    packet.FRMPayloadHex = bytesToHex(packet.FRMPayload);
  } else {
    packet.FPort = null;
    packet.FRMPayload = [];
    packet.FRMPayloadHex = "";
  }

  packet.MIC = bytes.slice(-4);
  packet.MICHex = bytesToHex(packet.MIC);

  return packet;
}
