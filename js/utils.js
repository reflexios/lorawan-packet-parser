window.hexToBytes = function (hex) {
  hex = hex.replace(/\s/g, "");
  if (hex.length % 2 !== 0) {
    throw new Error(I18N.t("errors.hexLength"));
  }
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
};

window.bytesToHex = function (bytes) {
  return Array.from(bytes, b =>
    b.toString(16).padStart(2, "0")
  ).join("");
};

window.reverseBytes = function (bytes) {
  return bytes.slice().reverse();
};

// from int from LE bytes
window.bytesToInt = function (bytes) {
  let result = 0;
  for (let i = 0; i < bytes.length; i++) {
    result |= bytes[i] << (8 * i);
  }
  return result;
};
