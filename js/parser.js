window.parseLoRaWANPacket = function (bytes) {
  if (bytes.length < 12) {
    throw new Error(I18N.t("errors.packetTooShort", { len: bytes.length }));
  }

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
    throw new Error(`FOptsLen too large: ${packet.FOptsLen}`);
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
};
