// Supported packet types for LoRaWAN 1.0.x
const SUPPORTED_DATA_PACKETS = [0x40, 0x60, 0x80, 0xA0]; // Unconf/Conf Up/Down
const SUPPORTED_JOIN_PACKETS = [0x00, 0x20]; // JoinRequest, JoinAccept
const PROPRIETARY_PACKET = 0xE0;

window.parseLoRaWANPacket = function (bytes) {
  if (bytes.length < 12) {
    throw new Error(I18N.t("errors.packetTooShort", { len: bytes.length }));
  }

  const mhdr = bytes[0];
  const mtype = mhdr & 0xe0;

  // Check for Proprietary packets - cannot process
  if (mtype === PROPRIETARY_PACKET) {
    throw new Error(I18N.t("errors.proprietaryPacket"));
  }

  // Check for unsupported packet types in current version (1.0.x)
  if (!SUPPORTED_DATA_PACKETS.includes(mtype) && !SUPPORTED_JOIN_PACKETS.includes(mtype)) {
    const mtypeStr = MTYPE[mtype] || `Unknown (0x${mtype.toString(16).padStart(2, "0")})`;
    throw new Error(I18N.t("errors.unsupportedPacketType", { type: mtypeStr }));
  }

  // For now, only data packets are fully supported
  // Join packets will be supported later
  if (SUPPORTED_JOIN_PACKETS.includes(mtype)) {
    if (mtype === 0x00) {
      return parseJoinRequest(bytes);
    } else {
      // JoinAccept (0x20) not yet supported
      throw new Error(I18N.t("errors.joinAcceptNotSupported"));
    }
  }

  // Parse data packet (Unconfirmed/Confirmed Up/Down)
  return parseDataPacket(bytes);
};

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
