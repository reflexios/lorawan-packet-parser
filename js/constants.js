window.MTYPE = {
  0x00: "Join Request",
  0x20: "Join Accept",
  0x40: "Unconfirmed Data Up",
  0x60: "Unconfirmed Data Down",
  0x80: "Confirmed Data Up",
  0xa0: "Confirmed Data Down",
  0xc0: "Rejoin Request",
  0xe0: "Proprietary",
};

window.FCTRL_UP = {
  ADR: 0x80,
  ADRACKReq: 0x40,
  ACK: 0x20,
  ClassB: 0x10,
};

window.FCTRL_DOWN = {
  ADR: 0x80,
  RFU: 0x40,
  ACK: 0x20,
  FPending: 0x10,
};
