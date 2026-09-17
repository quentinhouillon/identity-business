# WASM API

This package exposes Rust functionality to JavaScript/TypeScript through WebAssembly.

It provides:

* Graph operations
* Encryption and decryption
* Master key derivation
* Vault key generation

---

## Graph

### `dfs_wasm`

Runs a depth-first search on a graph.

```typescript
const visited = dfs_wasm(
    JSON.stringify(edges),
    startId
);
```

**Parameters:**

* `edges`: JSON string containing the graph edges
* `startId`: UUID of the starting node

**Returns:**

```typescript
Set<string>
```

containing the visited node IDs.

---

### `spof_wasm`

Finds Single Points of Failure in the graph.

```typescript
const spofs = spof_wasm(
    JSON.stringify(edges),
    startId
);
```

**Parameters:**

* `edges`: JSON string containing the graph edges
* `startId`: UUID of the starting node

**Returns:**

```typescript
string[]
```

containing the SPOF node IDs.

---

# Cryptography

The cryptographic API uses:

* 32-byte keys
* 24-byte nonces
* AEAD encryption
* Argon2id for password-based key derivation

Binary data is passed between JavaScript and WASM using `Uint8Array`.

---

## `encrypt_wasm`

Encrypts a JavaScript value.

```typescript
const key = new Uint8Array(32);

const nonce = crypto.getRandomValues(
    new Uint8Array(24)
);

const data = {
    username: "alice",
    password: "secret"
};

const encrypted = encrypt_wasm(
    key,
    nonce,
    data
);
```

### Parameters

| Parameter | Type         | Description            |
| --------- | ------------ | ---------------------- |
| `key`     | `Uint8Array` | 32-byte encryption key |
| `nonce`   | `Uint8Array` | 24-byte nonce          |
| `value`   | `any`        | JSON-compatible value  |

### Important

A **new nonce must be generated for every encryption with the same key**.

The nonce does not need to be secret and can be stored alongside the ciphertext.

---

## `decrypt_wasm`

Decrypts previously encrypted data.

```typescript
const decrypted = decrypt_wasm(
    key,
    nonce,
    encrypted
);
```

The same `key` and `nonce` used for encryption must be provided.

---

# Key Management

## `derive_master_key_wasm`

Derives a 32-byte master key from a password and a salt using Argon2id.

```typescript
const password = new TextEncoder().encode(
    "my password"
);

const salt = crypto.getRandomValues(
    new Uint8Array(16)
);

const masterKey = derive_master_key_wasm(
    password,
    salt
);
```

### Parameters

| Parameter        | Type         | Description            |
| ---------------- | ------------ | ---------------------- |
| `masterPassword` | `Uint8Array` | User password as bytes |
| `salt`           | `Uint8Array` | Random salt            |

### Returns

```typescript
Uint8Array
```

The returned key is always **32 bytes**.

The salt is not secret and should be stored with the encrypted data.

---

## `generate_vault_key_wasm`

Generates a cryptographically secure random 32-byte key.

```typescript
const vaultKey = generate_vault_key_wasm();
```

### Returns

```typescript
Uint8Array
```

containing 32 random bytes.

---

# Typical Vault Flow

A typical vault can use the API like this:

```text
Password
   │
   ▼
Argon2id
   │
   ▼
Master Key
   │
   ▼
Vault Key
   │
   ▼
AEAD Encryption
   │
   ├── Nonce (24 bytes)
   │
   └── Ciphertext
```

Example:

```typescript
const password = new TextEncoder().encode(
    "my password"
);

const salt = crypto.getRandomValues(
    new Uint8Array(16)
);

const masterKey = derive_master_key_wasm(
    password,
    salt
);

const vaultKey = generate_vault_key_wasm();

const nonce = crypto.getRandomValues(
    new Uint8Array(24)
);

const encrypted = encrypt_wasm(
    vaultKey,
    nonce,
    {
        username: "alice",
        password: "secret"
    }
);
```

---

# Security Notes

* Encryption keys must be **32 bytes**.
* Nonces must be **24 bytes**.
* Never reuse the same nonce with the same key.
* Nonces and salts do not need to be secret.
* Use a cryptographically secure random generator for salts, nonces, and random keys.
* Do not hard-code encryption keys or passwords.
* The master password should never be stored.
* WASM provides the cryptographic implementation but is **not a secure enclave**; secrets used by browser JavaScript should not be considered inaccessible to the JavaScript environment.
