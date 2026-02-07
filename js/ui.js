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
      // Data packets - use NwkSKey
      if (nwkSKeyHex) {
        try {
          micResult = verifyMIC(
            bytes,
            nwkSKeyHex,
            fcntUpContext,
            fcntDownContext,
          );
        } catch (e) {
          console.error("MIC verify error:", e);
          throw e;
        }
      }
    }

    let decryptResult = null;
    // Only data packets have payload to decrypt
    if (packet.FPort !== undefined && packet.FPort !== null && packet.FRMPayload && packet.FRMPayload.length > 0) {
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
          console.error("Payload decrypt error:", e);
          decryptResult = { error: e.message };
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
