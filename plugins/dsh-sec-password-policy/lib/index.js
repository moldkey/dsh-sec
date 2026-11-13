/**
 * 安全工具：password policy — 安全工具
 */

export const name = "dsh-sec-password-policy";
export const inject = ["tools"];

const NL = String.fromCharCode(10);
const SITE = "https://deepseekbase.com/zh/tools/";
const TEXT_OUTPUT = {
  schema: { type: "object", additionalProperties: false, properties: { text: { type: "string" } }, required: ["text"] },
  render: (_args, value) => [{ type: "text", text: (value && value.text) || "" }],
};

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const COMMON = ["123456", "password", "12345678", "qwerty", "111111", "abc123", "123456789", "admin", "letmein", "welcome", "monkey", "dragon", "iloveyou", "88888888"];
const WORDS = ["copper", "harbor", "lantern", "velvet", "anchor", "cactus", "marble", "puzzle", "rocket", "saddle", "timber", "walnut", "yonder", "zephyr", "breeze", "cinder"];
const enc = new TextEncoder();

function b32dec(s) { s = s.toUpperCase().replace(/=+$/, "").replace(/\s/g, ""); let bits = 0, val = 0; const out = []; for (const c of s) { const i = B32.indexOf(c); if (i < 0) throw new Error("非法 Base32 密钥"); val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); }
function b64u(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64uDec(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); }
function entropyOf(s) {
  const set = /[a-z]/.test(s) ? 26 : 0; const up = /[A-Z]/.test(s) ? 26 : 0; const d = /\d/.test(s) ? 10 : 0; const sym = /[^A-Za-z0-9]/.test(s) ? 33 : 0;
  return Array.from(s).length * Math.log2(set + up + d + sym || 1);
}
async function hmac(algo, keyText, text) {
  const key = await crypto.subtle.importKey("raw", enc.encode(keyText), { name: "HMAC", hash: algo }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(text));
  return Array.from(new Uint8Array(sig)).map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function hotpAt(secret, counter) {
  const key = await crypto.subtle.importKey("raw", b32dec(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const buf = new ArrayBuffer(8); const view = new DataView(buf); view.setUint32(4, counter >>> 0, false); view.setUint32(0, Math.floor(counter / 4294967296), false);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const off = sig[sig.length - 1] & 0x0f;
  const code = ((sig[off] & 0x7f) << 24) | ((sig[off + 1] & 0xff) << 16) | ((sig[off + 2] & 0xff) << 8) | (sig[off + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}
async function aesEncrypt(text, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text)));
  const all = new Uint8Array(salt.length + iv.length + ct.length);
  all.set(salt, 0); all.set(iv, salt.length); all.set(ct, salt.length + iv.length);
  return b64u(all);
}
async function aesDecrypt(payload, password) {
  const all = b64uDec(payload);
  const salt = all.slice(0, 16), iv = all.slice(16, 28), ct = all.slice(28);
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(pt);
}

const OPS = {
  password_strength: (t) => {
    const s = String(t); let score = 0;
    if (s.length >= 8) score++; if (s.length >= 12) score++; if (s.length >= 16) score++;
    if (/[a-z]/.test(s) && /[A-Z]/.test(s)) score++;
    if (/\d/.test(s)) score++;
    if (/[^A-Za-z0-9]/.test(s)) score++;
    if (COMMON.indexOf(s.toLowerCase()) >= 0) score = 0;
    const label = score >= 6 ? "很强" : score >= 5 ? "强" : score >= 3 ? "中等" : "弱";
    return "强度: " + label + "（" + score + "/6）" + NL + "熵: " + Math.round(entropyOf(s)) + " bits";
  },
  password_entropy: (t) => "熵: " + Math.round(entropyOf(String(t))) + " bits（<40 弱，40–60 中，>60 强）",
  password_policy: (t) => {
    const s = String(t);
    const checks = [["长度 ≥ 8", s.length >= 8], ["含小写", /[a-z]/.test(s)], ["含大写", /[A-Z]/.test(s)], ["含数字", /\d/.test(s)], ["含符号", /[^A-Za-z0-9]/.test(s)], ["不在常见弱密码表", COMMON.indexOf(s.toLowerCase()) < 0]];
    return checks.map((c) => (c[1] ? "PASS " : "FAIL ") + c[0]).join(NL);
  },
  weak_check: (t) => COMMON.indexOf(String(t).toLowerCase()) >= 0 ? "在常见弱密码表内" : "不在弱密码表",
  generate_password: (t, a) => { const len = Math.min(Math.max(8, Number(a) || 16), 128); const cs = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"; const buf = new Uint8Array(len); crypto.getRandomValues(buf); return Array.from(buf).map((x) => cs[x % cs.length]).join(""); },
  passphrase: (t, a) => { const n = Math.min(Math.max(2, Number(a) || 4), 8); const out = []; for (let i = 0; i < n; i++) { const b = new Uint32Array(1); crypto.getRandomValues(b); out.push(WORDS[b[0] % WORDS.length]); } return out.join("-"); },
  pin: (t, a) => { const n = Math.min(Math.max(4, Number(a) || 6), 12); const b = new Uint8Array(n); crypto.getRandomValues(b); return Array.from(b).map((x) => String(x % 10)).join(""); },
  totp: async (t, a) => { const step = 30; const counter = Math.floor(Date.now() / 1000 / step); const code = await hotpAt(String(t).trim(), counter); return "TOTP: " + code + NL + "剩余: " + (step - Math.floor(Date.now() / 1000) % step) + " 秒"; },
  hotp: async (t, a) => "HOTP: " + await hotpAt(String(t).trim(), Number(a) || 0),
  hmac_sha256: async (t, a) => "HMAC-SHA256: " + await hmac("SHA-256", String(a), String(t)),
  hmac_sha1: async (t, a) => "HMAC-SHA1: " + await hmac("SHA-1", String(a), String(t)),
  aes_encrypt: async (t, a) => "密文: " + await aesEncrypt(String(t), String(a)),
  aes_decrypt: async (t, a) => "明文: " + await aesDecrypt(String(t).trim(), String(a)),
  hash_identify: (t) => { const s = String(t).trim(); const types = { 32: "MD5 / NTLM", 40: "SHA-1", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512" }; return /^[0-9a-fA-F]+$/.test(s) ? "可能是 " + (types[s.length] || "未知") : "不是十六进制哈希"; },
  luhn: (t) => { const s = String(t).replace(/\D/g, ""); if (!s) return "需要数字"; let sum = 0; let dbl = false; for (let i = s.length - 1; i >= 0; i--) { let n = Number(s[i]); if (dbl) { n *= 2; if (n > 9) n -= 9; } sum += n; dbl = !dbl; } return sum % 10 === 0 ? "Luhn 校验通过" : "Luhn 校验失败"; },
  id_card_check: (t) => {
    const s = String(t).trim().toUpperCase();
    if (!/^\d{17}[\dX]$/.test(s)) return "格式不符（18 位）";
    const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]; const codes = "10X98765432";
    let sum = 0; for (let i = 0; i < 17; i++) sum += Number(s[i]) * w[i];
    return codes[sum % 11] === s[17] ? "身份证校验位正确" : "校验位错误（应为 " + codes[sum % 11] + "）";
  },
  email_validate: (t) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(t).trim()) ? "邮箱格式正确" : "邮箱格式错误",
  phone_validate: (t) => /^1[3-9]\d{9}$/.test(String(t).trim()) ? "手机号格式正确" : "手机号格式错误",
  secrets_scan: (t) => {
    const s = String(t); const hits = [];
    if (/ghp_[A-Za-z0-9]{20,}/.test(s)) hits.push("GitHub Token");
    if (/sk-[A-Za-z0-9]{20,}/.test(s)) hits.push("OpenAI/类 sk- 密钥");
    if (/AKIA[0-9A-Z]{16}/.test(s)) hits.push("AWS Access Key");
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)) hits.push("私钥");
    if (/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\./.test(s)) hits.push("JWT");
    if (/\b\d{16,19}\b/.test(s)) hits.push("疑似银行卡号");
    return hits.length ? "发现: " + hits.join(" / ") : "未发现常见密钥模式（不等于绝对安全）";
  },
  mask_api_key: (t) => { const s = String(t).trim(); return s.length <= 8 ? "****" : s.slice(0, 4) + "*".repeat(Math.max(4, s.length - 8)) + s.slice(-4); },
  url_safety: (t) => { try { const u = new URL(String(t).trim()); const out = ["协议: " + u.protocol]; out.push(u.protocol === "https:" ? "PASS HTTPS" : "WARN 非 HTTPS"); out.push(/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname) ? "WARN 使用 IP 地址" : "PASS 域名"); return out.join(NL); } catch (e) { return "URL 无效"; } },
  domain_safety: (t) => { const h = String(t).trim().toLowerCase(); const out = []; if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) out.push("WARN IP 直连"); if (/xn--/.test(h)) out.push("WARN Punycode 域名"); if (h.split(".").length > 3) out.push("WARN 子域层级多"); if (!out.length) out.push("PASS 无常见可疑特征"); return out.join(NL); },
};

export function apply(ctx, config) {
  void config;
  ctx.tools.register({
    name: "sec_password_policy",
    description: "password policy",
    parameters: {
      text: { "type": "string", required: true, "description": "输入" },
    },
    output: TEXT_OUTPUT,
    async execute(args) {
      const t = args && args.text != null ? String(args.text) : "";
      const a = args && args.a != null ? String(args.a) : "";
      try {
        const fn = OPS["password_policy"];
        if (!fn) throw new Error("未知操作");
        return { text: ["安全工具：password policy", "=".repeat(52), String(await fn(t, a)), "", "更多工具：" + SITE].join(NL) };
      } catch (e) {
        return { text: "处理失败: " + String((e && e.message) || e) };
      }
    },
  });
}
