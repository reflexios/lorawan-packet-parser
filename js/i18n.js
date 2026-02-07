window.I18N = {
  dict: {},

  async load(locale = "en") {
    const res = await fetch(`i18n/${locale}.json`);
    this.dict = await res.json();
  },

  t(key, vars = {}) {
    const parts = key.split(".");
    let value = this.dict;

    for (const p of parts) {
      value = value?.[p];
      if (!value) return key;
    }

    return value.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? `{${k}}`);
  },
};
