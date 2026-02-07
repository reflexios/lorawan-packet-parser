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

    const bytes = hexToBytes(hex);
    const packet = parseLoRaWANPacket(bytes);

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

    let decryptResult = null;
    if (packet.FPort !== null && packet.FRMPayload.length > 0) {
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
