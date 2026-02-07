window.formatPacketOutput = function (packet, micResult, decryptResult) {
  let output = `✅ ${I18N.t("result.success")}\n\n`;
  output += "═══════════════════════════════════════\n";
  output += `${I18N.t("labels.packetStructure")}:\n`;
  output += "═══════════════════════════════════════\n\n";

  output += `📋 MHDR: 0x${packet.MHDR.toString(16).padStart(2, "0").toUpperCase()}\n`;
  output += `   • MType: ${packet.MTypeStr} (0x${packet.MType.toString(16).padStart(2, "0").toUpperCase()})\n`;
  output += `   • Major: ${packet.Major}\n`;
  output += `   • ${I18N.t("labels.direction")}: ${
    packet.Direction === "up"
      ? I18N.t("labels.uplink")
      : I18N.t("labels.downlink")
  }\n\n`;

  output += `🆔 DevAddr: ${packet.DevAddrHex.toUpperCase()}\n`;
  output += `   • LE (wire): ${bytesToHex(packet.DevAddrLE).toUpperCase()}\n\n`;

  output += `⚙️  FCtrl: 0x${packet.FCtrl.toString(16).padStart(2, "0").toUpperCase()}\n`;
  output += `   • ADR: ${packet.ADR}\n`;
  if (packet.Direction === "up") {
    output += `   • ADRACKReq: ${packet.ADRACKReq}\n`;
    output += `   • ClassB: ${packet.ClassB}\n`;
  } else {
    output += `   • FPending: ${packet.FPending}\n`;
  }
  output += `   • ACK: ${packet.ACK}\n`;
  output += `   • FOptsLen: ${packet.FOptsLen}\n\n`;

  output += `🔢 FCnt: ${packet.FCnt}\n`;
  output += `   • LE (wire): ${bytesToHex(packet.FCntBytes).toUpperCase()}\n\n`;

  if (packet.FOpts.length > 0) {
    output += `📦 FOpts: ${packet.FOptsHex.toUpperCase()} (${packet.FOpts.length} bytes)\n\n`;
  }

  if (packet.FPort !== null) {
    output += `🚪 FPort: ${packet.FPort}\n\n`;
    output += `🔐 FRMPayload (encrypted): ${packet.FRMPayloadHex.toUpperCase()}\n`;
    output += `   • Length: ${packet.FRMPayload.length} bytes\n`;

    if (decryptResult) {
      if (decryptResult.error) {
        output += `\n⚠️ ${decryptResult.error}\n`;
      } else {
        output += `\n🔓 FRMPayload (decrypted):\n`;
        output += `   • HEX: ${bytesToHex(Array.from(decryptResult.decrypted)).toUpperCase()}\n`;

        const ascii = Array.from(decryptResult.decrypted)
          .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
          .join("");
        output += `   • ASCII: "${ascii}"\n`;
        output += `   • ${I18N.t("labels.keyUsed")}: ${decryptResult.keyUsed}\n`;
      }
    }
    output += "\n";
  }

  output += `🔒 MIC: ${packet.MICHex.toUpperCase()}\n`;

  if (micResult) {
    output += "\n═══════════════════════════════════════\n";
    output += `${I18N.t("result.micCheck")}:\n`;
    output += "═══════════════════════════════════════\n\n";

    if (micResult.valid) {
      output += `✅ ${I18N.t("result.micValid")}!\n`;
      output += `   • ${I18N.t("labels.micReceived")}: ${bytesToHex(Array.from(micResult.received)).toUpperCase()}\n`;
      output += `   • ${I18N.t("labels.micComputed")}: ${bytesToHex(Array.from(micResult.computed)).toUpperCase()}\n\n`;
    } else {
      output += `❌ ${I18N.t("result.micInvalid")}!\n`;
      output += `   • ${I18N.t("labels.micReceived")}: ${bytesToHex(Array.from(micResult.received)).toUpperCase()}\n`;
      output += `   • ${I18N.t("labels.micComputed")}: ${bytesToHex(Array.from(micResult.computed)).toUpperCase()}\n\n`;

      output += `📊 ${I18N.t("labels.usedFcnt")}:\n`;
      output += `   • ${I18N.t("labels.packetFcnt")}: ${micResult.packetFCnt}\n`;
      output += `   • ${I18N.t("labels.micFcnt")}: ${micResult.usedFCnt}\n`;
      if (micResult.contextProvided) {
        output += `   • ${I18N.t("labels.sourceContext")}\n`;
        output += `\n⚠️ ${I18N.t("labels.possibleContextError")}\n`;
      } else {
        output += `   • ${I18N.t("labels.sourcePacket")}\n`;
        output += `\n💡 ${I18N.t("labels.tryContext")}\n`;
      }
    }
  }

  return output;
};
