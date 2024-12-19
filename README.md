# Deformer

A robust JavaScript implementation for secure payload transformation, providing encryption, integrity checking, and key obfuscation for JSON data.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Implementation Details](#implementation-details)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Security Features](#security-features)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Features

- 🔐 AES-256-CBC encryption for all payload values
- 🔑 PBKDF2 key derivation with secure salting
- ✅ HMAC-SHA256 integrity verification
- 🎭 Key obfuscation with timestamp-based noise
- 📦 Support for nested objects and arrays
- 🛡️ Comprehensive error handling and validation
- 📝 Detailed logging and debugging capabilities

## Installation

### Prerequisites

- Node.js 14.x or higher
- npm or yarn package manager

### Setup

1. Install the packages:

```bash
npm install crypto-js dotenv
# or
yarn add crypto-js dotenv
```

2. Create environment configuration:

```bash
# Create .env file
touch .env

# Add encryption key
echo "PAYLOAD_NOISE_KEY=your-secure-encryption-key-here" >> .env
```

3. Import and initialize:

```javascript
const PayloadNoise = require('./PayloadNoise');
// or
import PayloadNoise from './PayloadNoise';

const noiseUtil = new PayloadNoise();
```

## Implementation Details

### Core Components

```javascript
class PayloadNoise {
    constructor(key = process.env.PAYLOAD_NOISE_KEY) {
        this.key = key;
    }

    // Main public methods
    encode(payload) { ... }
    decode(noisyPayload) { ... }

    // Private utility methods
    #generateNoisyKey(key, timestamp) { ... }
    #recoverOriginalKey(noisyKey) { ... }
    #generateHash(payload) { ... }
    #verifyHash(payload) { ... }
    #validatePayload(payload) { ... }
}
```

### Encryption Process

1. **Key Derivation**
```javascript
const salt = CryptoJS.lib.WordArray.random(16);
const derivedKey = CryptoJS.PBKDF2(this.key, salt, {
    keySize: 256 / 32,
    iterations: 1000
});
```

2. **Data Encryption**
```javascript
const iv = CryptoJS.lib.WordArray.random(16);
const encrypted = CryptoJS.AES.encrypt(valueStr, derivedKey, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
});
```

3. **Key Obfuscation**
```javascript
#generateNoisyKey(key, timestamp) {
    const hash = CryptoJS.SHA256(key + timestamp);
    return `${key}_${hash.toString(CryptoJS.enc.Hex).slice(0, 8)}`;
}
```

4. **Integrity Protection**
```javascript
#generateHash(payload) {
    const { _h, ...payloadWithoutHash } = payload;
    return CryptoJS.HmacSHA256(
        JSON.stringify(payloadWithoutHash), 
        this.key
    ).toString();
}
```

## Usage

### Basic Example

```javascript
const PayloadNoise = require('./PayloadNoise');

// Initialize with environment key
const noiseUtil = new PayloadNoise();

// Original data
const sensitiveData = {
    username: "john_doe",
    password: "secure_password",
    metadata: {
        lastLogin: new Date().toISOString(),
        roles: ["admin", "user"]
    }
};

try {
    // Encode data
    const encodedData = noiseUtil.encode(sensitiveData);
    console.log('Encoded:', encodedData);

    // Decode data
    const decodedData = noiseUtil.decode(encodedData);
    console.log('Decoded:', decodedData);
} catch (error) {
    console.error('Processing error:', error.message);
}
```

### Advanced Usage

#### Working with Complex Objects

```javascript
const complexData = {
    user: {
        id: 12345,
        profile: {
            name: "John Doe",
            email: "john@example.com",
            settings: {
                theme: "dark",
                notifications: true,
                preferences: ["email", "sms"]
            }
        }
    },
    session: {
        token: "eyJhbGci...",
        expires: new Date().toISOString()
    }
};

// Encode complex data
const encoded = noiseUtil.encode(complexData);

// The encoded payload structure will be:
{
    _v: "1.0",
    _t: 1734614127054,
    _s: "d815bd0b998476a5ab62913399e26bb2",
    _i: "f7f2e0cf300d2a11d26f91d694f87161",
    data: {
        "user_b648ee6a": "encrypted_data",
        "session_d47c8311": "encrypted_data"
    },
    _h: "b12afb712b629bb2ccf74b2c4c33139d..."
}
```

#### Error Handling

```javascript
try {
    const result = noiseUtil.decode(suspiciousPayload);
} catch (error) {
    if (error.message.includes('integrity check failed')) {
        console.error('Payload may have been tampered with');
    } else if (error.message.includes('Invalid payload structure')) {
        console.error('Malformed payload received');
    } else {
        console.error('Unexpected error:', error);
    }
}
```

## Security Features

### 1. Encryption

- **Algorithm**: AES-256-CBC
- **Key Derivation**: PBKDF2 with 1000 iterations
- **IV**: Unique per payload
- **Salt**: Random 16-byte value per payload
- **Padding**: PKCS7

### 2. Key Protection

- Environment-based key storage
- Key derivation using PBKDF2
- No key storage in encoded payload

### 3. Integrity

- HMAC-SHA256 for payload verification
- Full payload coverage in hash
- Timestamp-based replay protection

### 4. Key Obfuscation

- Original keys are never exposed
- Timestamp-based noise addition
- 8-byte random suffix per key

## Error Handling

### Error Types

1. **Input Validation Errors**
   - Invalid payload type
   - Missing required fields
   - Malformed data structure

2. **Cryptographic Errors**
   - Encryption failures
   - Decryption failures
   - Key derivation errors

3. **Integrity Errors**
   - Hash verification failures
   - Tampered payload detection
   - Invalid structure

### Error Handling Strategy

```javascript
class PayloadNoise {
    #validatePayload(payload) {
        const required = ['_v', '_t', '_s', '_i', '_h', 'data'];
        return required.every(field => payload[field]);
    }

    decode(noisyPayload) {
        try {
            // Structural validation
            if (!this.#validatePayload(noisyPayload)) {
                throw new Error('Invalid payload structure');
            }

            // Hash verification
            if (!this.#verifyHash(noisyPayload)) {
                throw new Error('Payload integrity check failed');
            }

            // Process fields with individual error handling
            for (const [key, value] of Object.entries(noisyPayload.data)) {
                try {
                    // Field processing
                } catch (fieldError) {
                    console.error(`Field processing error: ${key}`, fieldError);
                }
            }
        } catch (error) {
            throw new Error(`Decoding failed: ${error.message}`);
        }
    }
}
```

## Best Practices

### 1. Key Management

- Use strong, random encryption keys
- Implement key rotation
- Secure key storage
- Regular key auditing

### 2. Error Handling

- Implement comprehensive logging
- Use appropriate error types
- Handle field-level failures
- Provide meaningful error messages

### 3. Performance

- Cache PayloadNoise instances
- Implement request rate limiting
- Monitor encryption/decryption times
- Handle large payloads efficiently

### 4. Security

- Regular security audits
- Input validation
- Output encoding
- Secure error messages
