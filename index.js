// test.js
const dotenv = require("dotenv");
const CryptoJS = require("crypto-js");

// Load environment variables
dotenv.config();

class PayloadNoise {
  constructor(
    key = process.env.PAYLOAD_NOISE_KEY || "test-encryption-key-2024"
  ) {
    if (!key) {
      throw new Error(
        "Encryption key is required. Set PAYLOAD_NOISE_KEY environment variable or provide a key."
      );
    }
    this.key = key;
  }

  encode(payload) {
    try {
      if (typeof payload !== "object") {
        throw new Error("Payload must be an object");
      }

      const timestamp = Date.now();
      const noisyPayload = {};

      // Generate salt and IV
      const salt = CryptoJS.lib.WordArray.random(16);
      const iv = CryptoJS.lib.WordArray.random(16);

      // Derive key
      const derivedKey = CryptoJS.PBKDF2(this.key, salt, {
        keySize: 256 / 32,
        iterations: 1000,
      });

      // Process each field
      for (const [key, value] of Object.entries(payload)) {
        // Safely stringify value
        const valueStr = JSON.stringify(value);

        // Encrypt the value directly without additional noise
        const encrypted = CryptoJS.AES.encrypt(valueStr, derivedKey, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        });

        // Create noisy key
        const noisyKey = this.#generateNoisyKey(key, timestamp);

        // Store the encrypted value
        noisyPayload[noisyKey] = encrypted.toString();
      }

      // Create final payload
      const finalPayload = {
        _v: "1.0",
        _t: timestamp,
        _s: salt.toString(),
        _i: iv.toString(),
        data: noisyPayload,
      };

      // Add hash last
      finalPayload._h = this.#generateHash(finalPayload.data);

      return finalPayload;
    } catch (error) {
      console.error("Encoding error details:", error);
      throw new Error(`Encoding failed: ${error.message}`);
    }
  }

  decode(noisyPayload) {
    try {
      if (!this.#validatePayload(noisyPayload)) {
        throw new Error("Invalid payload structure");
      }

      const timestamp = noisyPayload._t;
      const salt = CryptoJS.enc.Hex.parse(noisyPayload._s);
      const iv = CryptoJS.enc.Hex.parse(noisyPayload._i);

      // Verify hash
      if (!this.#verifyHash(noisyPayload)) {
        throw new Error("Payload integrity check failed");
      }

      // Derive key
      const derivedKey = CryptoJS.PBKDF2(this.key, salt, {
        keySize: 256 / 32,
        iterations: 1000,
      });

      const originalPayload = {};

      // Decrypt each field
      for (const [noisyKey, encryptedValue] of Object.entries(
        noisyPayload.data
      )) {
        try {
          // Decrypt
          const decrypted = CryptoJS.AES.decrypt(encryptedValue, derivedKey, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
          });

          // Convert to UTF8 string and parse
          const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);
          const value = JSON.parse(decryptedStr);

          // Recover original key
          const originalKey = this.#recoverOriginalKey(noisyKey);

          originalPayload[originalKey] = value;
        } catch (fieldError) {
          console.error(`Error decoding field ${noisyKey}:`, fieldError);
          originalPayload[this.#recoverOriginalKey(noisyKey)] = null;
        }
      }

      return originalPayload;
    } catch (error) {
      console.error("Decoding error details:", error);
      throw new Error(`Decoding failed: ${error.message}`);
    }
  }

  // Private helper methods
  #generateNoisyKey(key, timestamp) {
    const hash = CryptoJS.SHA256(key + timestamp);
    return `${key}_${hash.toString(CryptoJS.enc.Hex).slice(0, 8)}`;
  }

  #recoverOriginalKey(noisyKey) {
    return noisyKey.split("_")[0];
  }

  #generateHash(payload) {
    return CryptoJS.HmacSHA256(JSON.stringify(payload), this.key).toString();
  }

  #verifyHash(payload) {
    const providedHash = payload._h;
    const { _h, ...payloadWithoutHash } = payload;
    const calculatedHash = this.#generateHash(payloadWithoutHash.data);
    return providedHash === calculatedHash;
  }

  #validatePayload(payload) {
    return (
      payload._v &&
      payload._t &&
      payload._s &&
      payload._i &&
      payload._h &&
      payload.data
    );
  }
}

// Create instance
const noiseUtil = new PayloadNoise();

// // Original payload
// const payload = {
//   username: "john_doe",
//   action: "login",
//   timestamp: 1234567890,
// };

// // Add noise before sending
// const noisyPayload = noiseUtil.encode(payload);
// console.log("Noisy payload:", noisyPayload);

const noisyPayload = {
  _v: "1.0",
  _t: 1734614571089,
  _s: "7286bc529aaf8e44196972cc00dd6319",
  _i: "9598bd7cad5e06bf0758e5d7fdef8e05",
  data: {
    tt_0787ade0: "QNzDEHYDlAGTsdV5pzTpUg==",
    tor_b1d772bb: "9EcP7Rync6MbMMHS1xF9TQ==",
    tk_26563096:
      "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",
  },
  _h: "76a68f18f7d6955a1bc988ff6e21712252512a5f32db552553054ac56976f505",
};

// Decode on receiver side
const originalPayload = noiseUtil.decode(noisyPayload);
console.log("Decoded payload:", originalPayload);
