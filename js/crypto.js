/**
 * Compute MIC for JoinRequest
 * @param {Uint8Array} key - AppKey for LoRaWAN 1.0.x (16 bytes)
 * @param {number} mhdr - MHDR byte
 * @param {Uint8Array} joinEuiLE - JoinEUI 8 bytes (LE)
 * @param {Uint8Array} devEuiLE - DevEUI 8 bytes (LE)
 * @param {number} devNonce - DevNonce (16-bit)
 * @returns {Uint8Array} MIC 4 bytes
 */
window.computeMICJoinRequest = function (key, mhdr, joinEuiLE, devEuiLE, devNonce) {
  if (key.length !== 16) {
    throw new Error(
      I18N.t("errors.mustBeBytes", {
        name: "AppKey",
        bytes: 16,
      }),
    );
  }
  if (joinEuiLE.length !== 8) {
    throw new Error(
      I18N.t("errors.mustBeBytes", {
        name: "JoinEUI",
        bytes: 8,
      }),
    );
  }
  if (devEuiLE.length !== 8) {
    throw new Error(
      I18N.t("errors.mustBeBytes", {
        name: "DevEUI",
        bytes: 8,
      }),
    );
  }

  // Block for CMAC: MHDR + JoinEUI + DevEUI + DevNonce
  const block = new Uint8Array(19);
  let offset = 0;

  block[offset++] = mhdr;

  // JoinEUI (8 bytes LE)
  for (let i = 0; i < 8; i++) {
    block[offset++] = joinEuiLE[i];
  }

  // DevEUI (8 bytes LE)
  for (let i = 0; i < 8; i++) {
    block[offset++] = devEuiLE[i];
  }

  // DevNonce (2 bytes LE)
  block[offset++] = devNonce & 0xff;
  block[offset++] = (devNonce >> 8) & 0xff;

  // AES-CMAC
  const fullCmac = asmCrypto.AES_CMAC.bytes(block, key);

  return new Uint8Array(fullCmac.slice(0, 4));
};

/**
 * Verify MIC for JoinRequest packet
 * @param {Array} packetBytes - full packet
 * @param {string} appKeyHex - AppKey in HEX
 * @returns {object} {valid: boolean, computed: Uint8Array, received: Uint8Array}
 */
window.verifyMICJoinRequest = function (packetBytes, appKeyHex) {
  if (!appKeyHex || appKeyHex.trim() === "") {
    throw new Error(I18N.t("errors.required", { name: "AppKey" }));
  }

  const appKey = new Uint8Array(hexToBytes(appKeyHex));

  if (packetBytes.length !== 23) {
    throw new Error(
      I18N.t("errors.joinRequestLength", { len: packetBytes.length }),
    );
  }

  const mhdr = packetBytes[0];
  const joinEuiLE = new Uint8Array(packetBytes.slice(1, 9));
  const devEuiLE = new Uint8Array(packetBytes.slice(9, 17));
  const devNonce = bytesToInt(packetBytes.slice(17, 19));

  const receivedMIC = new Uint8Array(packetBytes.slice(19, 23));

  const computedMIC = computeMICJoinRequest(
    appKey,
    mhdr,
    joinEuiLE,
    devEuiLE,
    devNonce,
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
  };
};

/**
 * Compute MIC LoRaWAN 1.0.x
 * @param {Uint8Array} nwkSKey  16 bytes
 * @param {number} direction   0 = uplink, 1 = downlink
 * @param {number} fcnt        uint32
 * @param {number} mhdr        1 byte
 * @param {Uint8Array} devAddr 4 bytes (LE)
 * @param {Uint8Array} macPayload bytes
 * @returns {Uint8Array} MIC 4 bytes
 */
window.computeMIC = function (
  nwkSKey,
  direction,
  fcnt,
  mhdr,
  devAddr,
  macPayload,
) {
  if (nwkSKey.length !== 16) {
    throw new Error(
      I18N.t("errors.mustBeBytes", {
        name: "NwkSKey",
        bytes: 16,
      }),
    );
  }
  if (devAddr.length !== 4) {
    throw new Error(
      I18N.t("errors.mustBeBytes", {
        name: "DevAddr",
        bytes: 4,
      }),
    );
  }

  // message = MHDR + MACPayload
  const message = new Uint8Array(1 + macPayload.length);
  message[0] = mhdr;
  message.set(macPayload, 1);

  const msgLength = message.length;

  // B0 block for AES-CMAC
  const b0 = new Uint8Array(16);
  b0[0] = 0x49;
  b0[1] = 0x00;
  b0[2] = 0x00;
  b0[3] = 0x00;
  b0[4] = 0x00;
  b0[5] = direction & 0xff;
  b0[6] = devAddr[0];
  b0[7] = devAddr[1];
  b0[8] = devAddr[2];
  b0[9] = devAddr[3];
  b0[10] = fcnt & 0xff;
  b0[11] = (fcnt >> 8) & 0xff;
  b0[12] = (fcnt >> 16) & 0xff;
  b0[13] = (fcnt >> 24) & 0xff;
  b0[14] = 0x00;
  b0[15] = msgLength & 0xff;

  // B0 + message
  const data = new Uint8Array(b0.length + message.length);
  data.set(b0, 0);
  data.set(message, b0.length);

  // AES-CMAC
  const fullCmac = asmCrypto.AES_CMAC.bytes(data, nwkSKey);

  return new Uint8Array(fullCmac.slice(0, 4));
};

/**
 * Decrypt FRMPayload
 * @param {Uint8Array} key - AppSKey (FPort > 0) or NwkSKey (FPort == 0)
 * @param {number} direction - 0 = uplink, 1 = downlink
 * @param {number} fcnt - FCnt (32-bit)
 * @param {Uint8Array} devAddr - 4 bytes (LE)
 * @param {Uint8Array} encryptedPayload - payload
 * @returns {Uint8Array} decrypted payload
 */
window.decryptPayload = function (
  key,
  direction,
  fcnt,
  devAddr,
  encryptedPayload,
) {
  if (key.length !== 16) {
    throw new Error(
      I18N.t("errors.mustBeBytes", {
        name: "Key (AppSKey if FPort > 0, NwkSKey if FPort == 0)",
        bytes: 16,
      }),
    );
  }
  if (devAddr.length !== 4) {
    throw new Error(
      I18N.t("errors.mustBeBytes", {
        name: "DevAddr",
        bytes: 4,
      }),
    );
  }
  if (encryptedPayload.length === 0) {
    return new Uint8Array(0);
  }

  // Block A for AES-CTR
  const blockA = new Uint8Array(16);
  blockA[0] = 0x01;
  blockA[1] = 0x00;
  blockA[2] = 0x00;
  blockA[3] = 0x00;
  blockA[4] = 0x00;
  blockA[5] = direction & 0xff;
  blockA[6] = devAddr[0]; // LSB
  blockA[7] = devAddr[1];
  blockA[8] = devAddr[2];
  blockA[9] = devAddr[3]; // MSB
  blockA[10] = fcnt & 0xff;
  blockA[11] = (fcnt >> 8) & 0xff;
  blockA[12] = (fcnt >> 16) & 0xff;
  blockA[13] = (fcnt >> 24) & 0xff;
  blockA[14] = 0x00;
  blockA[15] = 0x00; // block counter

  const decrypted = new Uint8Array(encryptedPayload.length);

  const numBlocks = Math.ceil(encryptedPayload.length / 16);

  for (let i = 0; i < numBlocks; i++) {
    const blockCount = (i + 1) & 0xff;
    blockA[15] = blockCount;

    // Encrypt ECB
    const blockS = asmCrypto.AES_ECB.encrypt(blockA, key);

    // XOR
    const blockStart = i * 16;
    const blockEnd = Math.min(blockStart + 16, encryptedPayload.length);
    const blockLength = blockEnd - blockStart;

    for (let j = 0; j < blockLength; j++) {
      decrypted[blockStart + j] = encryptedPayload[blockStart + j] ^ blockS[j];
    }
  }

  return decrypted;
};

/**
 * @param {Array} packetBytes
 * @param {number} fport
 * @param {Uint8Array} payload - encrypted payload
 * @param {string} appSKeyHex - AppSKey
 * @param {string} nwkSKeyHex - NwkSKey
 * @param {number|null} fcntUpContext - FCntUp from Network Server
 * @param {number|null} fcntDownContext - FCntDown from Network Server
 * @returns {object} {decrypted: Uint8Array, keyUsed: string, fcntUsed: number}
 */
window.decryptPacketPayload = function (
  packetBytes,
  fport,
  payload,
  appSKeyHex,
  nwkSKeyHex,
  fcntUpContext,
  fcntDownContext,
) {
  if (payload.length === 0) {
    throw new Error(I18N.t("errors.payloadEmpty"));
  }

  // Select key by FPort
  let keyHex, keyUsed;
  if (fport === 0) {
    if (!nwkSKeyHex || nwkSKeyHex.trim() === "") {
      throw new Error(I18N.t("errors.required", { name: "NwkSKey" }));
    }
    keyHex = nwkSKeyHex;
    keyUsed = "NwkSKey";
  } else {
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
  const contextFCnt = isUplink ? fcntUpContext : fcntDownContext;
  const fullFCnt = getFullFCnt(packetFCnt, contextFCnt);

  const decrypted = decryptPayload(key, direction, fullFCnt, devAddr, payload);

  return {
    decrypted: decrypted,
    keyUsed: keyUsed,
    fcntUsed: fullFCnt,
  };
};

/**
 * @param {number} packetFCnt - FCnt from packet uint16
 * @param {number|null} contextFCnt - FCnt from Network Server uint32 or null
 * @returns {number} FCnt
 */
window.getFullFCnt = function (packetFCnt, contextFCnt) {
  if (contextFCnt === null || contextFCnt === undefined) {
    return packetFCnt;
  }

  const contextUpper = (contextFCnt >> 16) & 0xffff;
  const packetLower = packetFCnt & 0xffff;

  let fullFCnt = (contextUpper << 16) | packetLower;

  const contextLower = contextFCnt & 0xffff;
  if (packetLower < contextLower && contextLower - packetLower > 32768) {
    fullFCnt = ((contextUpper + 1) << 16) | packetLower;
  }

  return fullFCnt;
};

/**
 * MIC verify
 * @param {Array} packetBytes
 * @param {string} nwkSKeyHex
 * @param {number|null} fcntUpContext - FCntUp from Network Server uint32 or null
 * @param {number|null} fcntDownContext - FCntDown from Network Server uint32 or null
 * @returns {object} {valid: boolean, computed: Uint8Array, received: Uint8Array, usedFCnt: number}
 */
window.verifyMIC = function (
  packetBytes,
  nwkSKeyHex,
  fcntUpContext,
  fcntDownContext,
) {
  if (!nwkSKeyHex || nwkSKeyHex.trim() === "") {
    throw new Error(I18N.t("errors.required", { name: "NwkSKey" }));
  }

  const nwkSKey = new Uint8Array(hexToBytes(nwkSKeyHex));

  if (packetBytes.length < 12) {
    throw new Error(
      I18N.t("errors.packetTooShort", { len: packetBytes.length }),
    );
  }

  const mhdr = packetBytes[0];
  const mtype = mhdr & 0xe0;

  const isUplink = mtype === 0x40 || mtype === 0x80;
  const direction = isUplink ? 0 : 1;

  const devAddr = new Uint8Array(packetBytes.slice(1, 5));

  const packetFCnt = bytesToInt(packetBytes.slice(6, 8));

  const contextFCnt = isUplink ? fcntUpContext : fcntDownContext;
  const fullFCnt = getFullFCnt(packetFCnt, contextFCnt);

  const macPayload = new Uint8Array(
    packetBytes.slice(1, packetBytes.length - 4),
  );

  const receivedMIC = new Uint8Array(packetBytes.slice(-4));

  const computedMIC = computeMIC(
    nwkSKey,
    direction,
    fullFCnt,
    mhdr,
    devAddr,
    macPayload,
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
