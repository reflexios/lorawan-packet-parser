/**
 * LoRaWAN 1.1 Cryptographic Functions
 *
 * Key differences from 1.0.x:
 * - Payload encryption for FPort=0 uses NwkSEncKey (not NwkSKey)
 * - Downlink uses AFCntDown (app) or NFCntDown (network) depending on FPort
 * - MIC calculation uses different keys and additional parameters
 */

/**
 * Compute MIC for LoRaWAN 1.1 data packets
 * @param {Uint8Array} fnwkSIntKey - FNwkSIntKey (16 bytes)
 * @param {Uint8Array} snwkSIntKey - SNwkSIntKey (16 bytes)
 * @param {number} direction - 0 = uplink, 1 = downlink
 * @param {number} fcnt - Full FCnt (32-bit)
 * @param {number|null} confFCnt - FCnt of last Confirmed packet (16-bit), required if ACK=1
 * @param {number|null} txDR - TX data rate (required for uplink)
 * @param {number|null} txCH - TX channel index (required for uplink)
 * @param {number} mhdr - MHDR byte
 * @param {Uint8Array} devAddr - DevAddr 4 bytes (LE)
 * @param {Uint8Array} macPayload - MACPayload (without MIC)
 * @param {boolean} ackBit - ACK bit from FCtrl
 * @returns {Uint8Array} MIC 4 bytes
 */
window.computeMIC11 = function(
  fnwkSIntKey,
  snwkSIntKey,
  direction,
  fcnt,
  confFCnt,
  txDR,
  txCH,
  mhdr,
  devAddr,
  macPayload,
  ackBit
) {
  if (fnwkSIntKey.length !== 16) {
    throw new Error(I18N.t("errors.mustBeBytes", { name: "FNwkSIntKey", bytes: 16 }));
  }
  if (snwkSIntKey.length !== 16) {
    throw new Error(I18N.t("errors.mustBeBytes", { name: "SNwkSIntKey", bytes: 16 }));
  }
  if (devAddr.length !== 4) {
    throw new Error(I18N.t("errors.mustBeBytes", { name: "DevAddr", bytes: 4 }));
  }

  // Set ConfFCnt for B0, B1 blocks based on direction
  let confFCntB0 = 0;
  let confFCntB1 = 0;

  if (ackBit) {
    if (confFCnt === null || confFCnt === undefined) {
      throw new Error("ACK bit is set, ConfFCnt is required");
    }
    if (direction === 0) {
      // Uplink with ACK: confirms downlink Conf packet
      confFCntB1 = confFCnt & 0xFFFF;
    } else {
      // Downlink with ACK: confirms uplink Conf packet
      confFCntB0 = confFCnt & 0xFFFF;
    }
  }

  // Set key for B0 block and txCH, txDR for B1 block based on direction
  let txChValue, txDrValue, keyB0;

  if (direction === 1) {
    // Downlink
    txChValue = 0;
    txDrValue = 0;
    keyB0 = snwkSIntKey;
  } else {
    // Uplink
    if (txCH === null || txCH === undefined || txDR === null || txDR === undefined) {
      throw new Error("Uplink packets require TxCH and TxDR");
    }
    txChValue = txCH & 0xFF;
    txDrValue = txDR & 0xFF;
    keyB0 = fnwkSIntKey;
  }

  // Message = MHDR + MACPayload
  const msgLength = 1 + macPayload.length;
  const message = new Uint8Array(msgLength);
  message[0] = mhdr;
  message.set(macPayload, 1);

  // B0 block for cmacF
  const b0 = new Uint8Array(16);
  b0[0] = 0x49;
  b0[1] = confFCntB0 & 0xFF;
  b0[2] = (confFCntB0 >> 8) & 0xFF;
  b0[3] = 0x00;
  b0[4] = 0x00;
  b0[5] = direction & 0xFF;
  b0[6] = devAddr[0];
  b0[7] = devAddr[1];
  b0[8] = devAddr[2];
  b0[9] = devAddr[3];
  b0[10] = fcnt & 0xFF;
  b0[11] = (fcnt >> 8) & 0xFF;
  b0[12] = (fcnt >> 16) & 0xFF;
  b0[13] = (fcnt >> 24) & 0xFF;
  b0[14] = 0x00;
  b0[15] = msgLength & 0xFF;

  // Compute cmacF (B0 + message)
  const dataF = new Uint8Array(b0.length + message.length);
  dataF.set(b0, 0);
  dataF.set(message, b0.length);
  const cmacF = asmCrypto.AES_CMAC.bytes(dataF, keyB0);

  if (direction === 1) {
    // Downlink: MIC = first 4 bytes of cmacF
    return new Uint8Array(cmacF.slice(0, 4));
  } else {
    // Uplink: compute cmacS and combine

    // B1 block for cmacS
    const b1 = new Uint8Array(16);
    b1[0] = 0x49;
    b1[1] = confFCntB1 & 0xFF;
    b1[2] = (confFCntB1 >> 8) & 0xFF;
    b1[3] = txDrValue;
    b1[4] = txChValue;
    b1[5] = direction & 0xFF;
    b1[6] = devAddr[0];
    b1[7] = devAddr[1];
    b1[8] = devAddr[2];
    b1[9] = devAddr[3];
    b1[10] = fcnt & 0xFF;
    b1[11] = (fcnt >> 8) & 0xFF;
    b1[12] = (fcnt >> 16) & 0xFF;
    b1[13] = (fcnt >> 24) & 0xFF;
    b1[14] = 0x00;
    b1[15] = msgLength & 0xFF;

    // Compute cmacS (B1 + message)
    const dataS = new Uint8Array(b1.length + message.length);
    dataS.set(b1, 0);
    dataS.set(message, b1.length);
    const cmacS = asmCrypto.AES_CMAC.bytes(dataS, snwkSIntKey);

    // Uplink MIC = [cmacS[0], cmacS[1], cmacF[0], cmacF[1]]
    return new Uint8Array([cmacS[0], cmacS[1], cmacF[0], cmacF[1]]);
  }
};

/**
 * Verify MIC for LoRaWAN 1.1 data packet
 * @param {Array} packetBytes - full packet
 * @param {string} fnwkSIntKeyHex - FNwkSIntKey in HEX
 * @param {string} snwkSIntKeyHex - SNwkSIntKey in HEX
 * @param {number|null} fcntUpContext - FCntUp from Network Server
 * @param {number|null} afcntDownContext - AFCntDown from Network Server
 * @param {number|null} nfcntDownContext - NFCntDown from Network Server
 * @param {number|null} confFCnt - ConfFCnt (16-bit)
 * @param {number|null} txDR - TX data rate (for uplink)
 * @param {number|null} txCH - TX channel (for uplink)
 * @returns {object} {valid: boolean, computed: Uint8Array, received: Uint8Array, usedFCnt: number, packetFCnt: number, contextProvided: boolean}
 */
window.verifyMIC11 = function(
  packetBytes,
  fnwkSIntKeyHex,
  snwkSIntKeyHex,
  fcntUpContext,
  afcntDownContext,
  nfcntDownContext,
  confFCnt,
  txDR,
  txCH
) {
  if (!fnwkSIntKeyHex || fnwkSIntKeyHex.trim() === "") {
    throw new Error(I18N.t("errors.required", { name: "FNwkSIntKey" }));
  }
  if (!snwkSIntKeyHex || snwkSIntKeyHex.trim() === "") {
    throw new Error(I18N.t("errors.required", { name: "SNwkSIntKey" }));
  }

  const fnwkSIntKey = new Uint8Array(hexToBytes(fnwkSIntKeyHex));
  const snwkSIntKey = new Uint8Array(hexToBytes(snwkSIntKeyHex));

  if (packetBytes.length < 12) {
    throw new Error(I18N.t("errors.packetTooShort", { len: packetBytes.length }));
  }

  const mhdr = packetBytes[0];
  const mtype = mhdr & 0xe0;

  const isUplink = mtype === 0x40 || mtype === 0x80;
  const direction = isUplink ? 0 : 1;

  const devAddr = new Uint8Array(packetBytes.slice(1, 5));
  const fctrl = packetBytes[5];
  const ackBit = !!(fctrl & 0x20);

  const packetFCnt = bytesToInt(packetBytes.slice(6, 8));

  // Select appropriate FCnt context
  let contextFCnt;
  if (isUplink) {
    contextFCnt = fcntUpContext;
  } else {
    // Downlink: need to know FPort to select AFCntDown vs NFCntDown
    const foptsLen = fctrl & 0x0F;
    const fportOffset = 1 + 4 + 1 + 2 + foptsLen; // MHDR + DevAddr + FCtrl + FCnt + FOpts

    if (packetBytes.length > fportOffset + 4) { // Has FPort
      const fport = packetBytes[fportOffset];
      contextFCnt = fport > 0 ? afcntDownContext : nfcntDownContext;
    } else {
      // No FPort, assume network downlink
      contextFCnt = nfcntDownContext;
    }
  }

  const fullFCnt = getFullFCnt(packetFCnt, contextFCnt);

  const macPayload = new Uint8Array(packetBytes.slice(1, packetBytes.length - 4));
  const receivedMIC = new Uint8Array(packetBytes.slice(-4));

  const computedMIC = computeMIC11(
    fnwkSIntKey,
    snwkSIntKey,
    direction,
    fullFCnt,
    confFCnt,
    txDR,
    txCH,
    mhdr,
    devAddr,
    macPayload,
    ackBit
  );

  let valid = true;
  for (let i = 0; i < 4; i++) {
    if (computedMIC[i] !== receivedMIC[i]) {
      valid = false;
      break;
    }
  }

  return {
    valid: valid,
    computed: computedMIC,
    received: receivedMIC,
    usedFCnt: fullFCnt,
    packetFCnt: packetFCnt,
    contextProvided: contextFCnt !== null && contextFCnt !== undefined,
  };
};

/**
 * Decrypt FRMPayload for LoRaWAN 1.1 data packets
 * @param {Array} packetBytes - full packet
 * @param {number} fport - FPort from packet
 * @param {Uint8Array} payload - encrypted payload
 * @param {string} appSKeyHex - AppSKey (for FPort > 0)
 * @param {string} nwkSEncKeyHex - NwkSEncKey (for FPort == 0)
 * @param {number|null} fcntUpContext - FCntUp from Network Server
 * @param {number|null} afcntDownContext - AFCntDown from Network Server (application downlink)
 * @param {number|null} nfcntDownContext - NFCntDown from Network Server (network downlink)
 * @returns {object} {decrypted: Uint8Array, keyUsed: string, fcntUsed: number}
 */
window.decryptPacketPayload11 = function (
  packetBytes,
  fport,
  payload,
  appSKeyHex,
  nwkSEncKeyHex,
  fcntUpContext,
  afcntDownContext,
  nfcntDownContext,
) {
  if (payload.length === 0) {
    throw new Error(I18N.t("errors.payloadEmpty"));
  }

  // Select key by FPort
  let keyHex, keyUsed;
  if (fport === 0) {
    // FPort == 0: MAC commands encrypted with NwkSEncKey
    if (!nwkSEncKeyHex || nwkSEncKeyHex.trim() === "") {
      throw new Error(I18N.t("errors.required", { name: "NwkSEncKey" }));
    }
    keyHex = nwkSEncKeyHex;
    keyUsed = "NwkSEncKey";
  } else {
    // FPort > 0: Application payload encrypted with AppSKey
    if (!appSKeyHex || appSKeyHex.trim() === "") {
      throw new Error(I18N.t("errors.required", { name: "AppSKey" }));
    }
    keyHex = appSKeyHex;
    keyUsed = "AppSKey";
  }

  const key = new Uint8Array(hexToBytes(keyHex));

  const mhdr = packetBytes[0];
  const mtype = mhdr & 0xe0;

  const isUplink = mtype === 0x40 || mtype === 0x80;
  const direction = isUplink ? 0 : 1;

  const devAddr = new Uint8Array(packetBytes.slice(1, 5));

  const packetFCnt = bytesToInt(packetBytes.slice(6, 8));

  // Select appropriate FCnt context based on direction and FPort
  let contextFCnt;
  if (isUplink) {
    // Uplink: always use FCntUp
    contextFCnt = fcntUpContext;
  } else {
    // Downlink: use AFCntDown (app) or NFCntDown (network) depending on FPort
    if (fport > 0) {
      // Application downlink
      contextFCnt = afcntDownContext;
    } else {
      // Network downlink (MAC commands)
      contextFCnt = nfcntDownContext;
    }
  }

  const fullFCnt = getFullFCnt(packetFCnt, contextFCnt);

  // Use the same decryptPayload function as 1.0.x (it's just AES-CTR)
  const decrypted = decryptPayload(key, direction, fullFCnt, devAddr, payload);

  return {
    decrypted: decrypted,
    keyUsed: keyUsed,
    fcntUsed: fullFCnt,
  };
};
