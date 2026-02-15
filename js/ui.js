document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("decodeBtn").onclick = decodePacket;
  document.getElementById("clearAllBtn").onclick = clearAll;

  document.querySelectorAll('input[type="text"]').forEach((input) => {
    input.addEventListener("keypress", function (e) {
      if (e.key === "Enter") {
        decodePacket();
      }
    });
  });
});

function decodePacket() {
  const result = document.getElementById("result");

  try {
    const hex = document.getElementById("packetHex").value.trim();
    if (!hex) {
      throw new Error(I18N.t("errors.enterHex"));
    }

    // OTAA key (for Join packets)
    const appKeyHex = document.getElementById("appKey").value.trim();

    const bytes = hexToBytes(hex);
    const packet = parseLoRaWANPacket(bytes, appKeyHex);

    // ABP keys (for Data packets)
    const nwkSKeyHex = document.getElementById("nwkSKey").value.trim();
    const appSKeyHex = document.getElementById("appSKey").value.trim();

    const fcntUpStr = document.getElementById("fcntUp").value.trim();
    const fcntDownStr = document.getElementById("fcntDown").value.trim();

    const fcntUpContext = fcntUpStr ? parseInt(fcntUpStr, 10) : null;
    const fcntDownContext = fcntDownStr ? parseInt(fcntDownStr, 10) : null;

    if (fcntUpStr && (isNaN(fcntUpContext) || fcntUpContext < 0)) {
      throw new Error(I18N.t("errors.fcntUpInvalid"));
    }
    if (fcntDownStr && (isNaN(fcntDownContext) || fcntDownContext < 0)) {
      throw new Error(I18N.t("errors.fcntDownInvalid"));
    }

    let micResult = null;

    // Check packet type for MIC verification
    if (packet.MType === 0x00) {
      // JoinRequest - use AppKey
      if (appKeyHex) {
        try {
          micResult = verifyMICJoinRequest(bytes, appKeyHex);
        } catch (e) {
          console.error("MIC verify error (JoinRequest):", e);
          throw e;
        }
      }
    } else if (packet.MType === 0x20) {
      // JoinAccept - use AppKey
      if (appKeyHex) {
        try {
          micResult = verifyMICJoinAccept(bytes, appKeyHex);
        } catch (e) {
          console.error("MIC verify error (JoinAccept):", e);
          throw e;
        }
      }
    } else {
      // Data packets - check version
      const version = getLoRaWANVersion();

      if (version === "1.0") {
        // LoRaWAN 1.0.x - use NwkSKey
        if (nwkSKeyHex) {
          try {
            micResult = verifyMIC(
              bytes,
              nwkSKeyHex,
              fcntUpContext,
              fcntDownContext,
            );
          } catch (e) {
            console.error("MIC verify error (1.0.x):", e);
            throw e;
          }
        }
      } else {
        // LoRaWAN 1.1 - use FNwkSIntKey and SNwkSIntKey
        const fnwkSIntKeyHex = document.getElementById("fnwkSIntKey").value.trim();
        const snwkSIntKeyHex = document.getElementById("snwkSIntKey").value.trim();

        const fcntUp11Str = document.getElementById("fcntUp11").value.trim();
        const afcntDownStr = document.getElementById("afcntDown").value.trim();
        const nfcntDownStr = document.getElementById("nfcntDown").value.trim();
        const confFCntStr = document.getElementById("confFCnt").value.trim();
        const txDRStr = document.getElementById("txDR").value.trim();
        const txCHStr = document.getElementById("txCH").value.trim();

        const fcntUp11Context = fcntUp11Str ? parseInt(fcntUp11Str, 10) : null;
        const afcntDownContext = afcntDownStr ? parseInt(afcntDownStr, 10) : null;
        const nfcntDownContext = nfcntDownStr ? parseInt(nfcntDownStr, 10) : null;
        const confFCnt = confFCntStr ? parseInt(confFCntStr, 10) : null;
        const txDR = txDRStr ? parseInt(txDRStr, 10) : null;
        const txCH = txCHStr ? parseInt(txCHStr, 10) : null;

        if (fnwkSIntKeyHex && snwkSIntKeyHex) {
          try {
            micResult = verifyMIC11(
              bytes,
              fnwkSIntKeyHex,
              snwkSIntKeyHex,
              fcntUp11Context,
              afcntDownContext,
              nfcntDownContext,
              confFCnt,
              txDR,
              txCH
            );
          } catch (e) {
            console.error("MIC verify error (1.1):", e);
            throw e;
          }
        }
      }
    }

    let decryptResult = null;
    // Only data packets have payload to decrypt
    if (packet.FPort !== undefined && packet.FPort !== null && packet.FRMPayload && packet.FRMPayload.length > 0) {
      const version = getLoRaWANVersion();

      if (version === "1.0") {
        // LoRaWAN 1.0.x decryption
        if (appSKeyHex || nwkSKeyHex) {
          try {
            decryptResult = decryptPacketPayload(
              bytes,
              packet.FPort,
              packet.FRMPayload,
              appSKeyHex,
              nwkSKeyHex,
              fcntUpContext,
              fcntDownContext,
            );
          } catch (e) {
            console.error("Payload decrypt error (1.0.x):", e);
            decryptResult = { error: e.message };
          }
        }
      } else {
        // LoRaWAN 1.1 decryption
        const appSKey11Hex = document.getElementById("appSKey11").value.trim();
        const nwkSEncKeyHex = document.getElementById("nwkSEncKey").value.trim();

        const fcntUp11Str = document.getElementById("fcntUp11").value.trim();
        const afcntDownStr = document.getElementById("afcntDown").value.trim();
        const nfcntDownStr = document.getElementById("nfcntDown").value.trim();

        const fcntUp11Context = fcntUp11Str ? parseInt(fcntUp11Str, 10) : null;
        const afcntDownContext = afcntDownStr ? parseInt(afcntDownStr, 10) : null;
        const nfcntDownContext = nfcntDownStr ? parseInt(nfcntDownStr, 10) : null;

        if (appSKey11Hex || nwkSEncKeyHex) {
          try {
            decryptResult = decryptPacketPayload11(
              bytes,
              packet.FPort,
              packet.FRMPayload,
              appSKey11Hex,
              nwkSEncKeyHex,
              fcntUp11Context,
              afcntDownContext,
              nfcntDownContext,
            );
          } catch (e) {
            console.error("Payload decrypt error (1.1):", e);
            decryptResult = { error: e.message };
          }
        }
      }
    }

    const output = formatPacketOutput(packet, micResult, decryptResult);

    result.className = "result-box success";
    result.innerHTML = `<pre>${output}</pre>`;
  } catch (e) {
    result.className = "result-box error";
    result.innerHTML = `<pre class="error-text">❌ ${e.message}</pre>`;
    console.error("Decode error:", e);
  }
}

function clearAll() {
  document
    .querySelectorAll('input[type="text"]')
    .forEach((i) => (i.value = ""));
  const result = document.getElementById("result");
  result.className = "result-box";
  result.innerHTML = `<pre>${I18N.t("result.empty")}</pre>`;
}

/**
 * LoRaWAN Version Switcher
 * Handles UI changes between 1.0.x and 1.1
 */

document.addEventListener("DOMContentLoaded", () => {
  const version10Radio = document.getElementById("version10");
  const version11Radio = document.getElementById("version11");

  const keys10x = document.getElementById("keys-10x");
  const keys11 = document.getElementById("keys-11");
  const context10x = document.getElementById("context-10x");
  const context11 = document.getElementById("context-11");

  function switchVersion() {
    if (version10Radio.checked) {
      // Show 1.0.x UI
      keys10x.style.display = "block";
      keys11.style.display = "none";
      context10x.style.display = "block";
      context11.style.display = "none";
    } else {
      // Show 1.1 UI
      keys10x.style.display = "none";
      keys11.style.display = "block";
      context10x.style.display = "none";
      context11.style.display = "block";
    }
  }

  // Add event listeners
  version10Radio.addEventListener("change", switchVersion);
  version11Radio.addEventListener("change", switchVersion);

  // Initialize
  switchVersion();
});

/**
 * Get current selected LoRaWAN version
 * @returns {string} "1.0" or "1.1"
 */
window.getLoRaWANVersion = function() {
  const version10Radio = document.getElementById("version10");
  return version10Radio.checked ? "1.0" : "1.1";
};
