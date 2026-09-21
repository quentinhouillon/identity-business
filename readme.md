# WASM API

This package exposes Rust functionality to JavaScript/TypeScript through WebAssembly.

It provides:

* Password breach checking
* Graph operations
* Encryption and decryption
* Master key derivation
* Vault key generation
* TOTP code generation

Binary data is passed using `Uint8Array`.

---

# Password Security

## `check_passwords_wasm`

Checks passwords against the Have I Been Pwned service.

```typescript
const results = await check_passwords_wasm([
    "password123",
    "my-password"
]);
```

### Parameters

| Parameter   | Type       | Description        |
| ----------- | ---------- | ------------------ |
| `passwords` | `string[]` | Passwords to check |

### Returns

```typescript
Promise<any>
```

Returns the results from the password breach check.

---

# Graph

## `dfs_wasm`

Runs a Depth-First Search (DFS) on a graph.

```typescript
const visited = dfs_wasm(
    JSON.stringify(edges),
    startId
);
```

### Parameters

| Parameter   | Type     | Description         |
| ----------- | -------- | ------------------- |
| `edgesJson` | `string` | Graph edges as JSON |
| `startId`   | `string` | Starting node UUID  |

### Returns

```typescript
Set<string>
```

A set containing the visited node IDs.

---

## `spof_wasm`

Finds Single Points of Failure (SPOF) in a graph.

```typescript
const spofs = spof_wasm(
    JSON.stringify(edges),
    startId
);
```

### Parameters

| Parameter   | Type     | Description         |
| ----------- | -------- | ------------------- |
| `edgesJson` | `string` | Graph edges as JSON |
| `startId`   | `string` | Starting node UUID  |

### Returns

```typescript
string[]
```

An array containing the SPOF node IDs.

---

# Cryptography

The cryptographic API uses:

* 32-byte keys
* 24-byte nonces
* AEAD encryption
* Argon2id for password-based key derivation

## `encrypt_wasm`

Encrypts a JSON-compatible JavaScript value.

```typescript
const encrypted = encrypt_wasm(
    key,
    nonce,
    {
        username: "alice",
        password: "secret"
    }
);
```

### Parameters

| Parameter | Type         | Description            |
| --------- | ------------ | ---------------------- |
| `key`     | `Uint8Array` | 32-byte encryption key |
| `nonce`   | `Uint8Array` | 24-byte nonce          |
| `value`   | `any`        | JSON-compatible value  |

A **new nonce must be used for every encryption with the same key**.

The nonce does not need to be secret.

---

## `decrypt_wasm`

Decrypts data previously encrypted with `encrypt_wasm`.

```typescript
const decrypted = decrypt_wasm(
    key,
    nonce,
    encrypted
);
```

### Parameters

| Parameter | Type         | Description            |
| --------- | ------------ | ---------------------- |
| `key`     | `Uint8Array` | 32-byte encryption key |
| `nonce`   | `Uint8Array` | 24-byte nonce          |
| `value`   | `any`        | Encrypted value        |

The same key and nonce used for encryption must be provided.

---

# Key Management

## `derive_master_key_wasm`

Derives a 32-byte master key from a password using Argon2id.

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

| Parameter        | Type         | Description    |
| ---------------- | ------------ | -------------- |
| `masterPassword` | `Uint8Array` | Password bytes |
| `salt`           | `Uint8Array` | Random salt    |

### Returns

```typescript
Uint8Array
```

A 32-byte master key.

The salt is not secret and can be stored with the encrypted data.

---

## `generate_vault_key_wasm`

Generates a random 32-byte vault key.

```typescript
const vaultKey = generate_vault_key_wasm();
```

### Returns

```typescript
Uint8Array
```

A cryptographically secure 32-byte key.

---

# TOTP

## `get_totp_code`

Generates a TOTP code for a node.

```typescript
const code = get_totp_code(
    node,
    timestamp
);
```

### Parameters

| Parameter   | Type     | Description                            |
| ----------- | -------- | -------------------------------------- |
| `node`      | `Node`   | Node containing the TOTP configuration |
| `timestamp` | `number` | Unix timestamp                         |

### Returns

```typescript
string
```

The generated TOTP code.

### Example

```typescript
const code = get_totp_code(
    node,
    Math.floor(Date.now() / 1000)
);

console.log(code);
```

---

# Security Notes

* Use **32-byte keys**.
* Use **24-byte nonces**.
* Never reuse a nonce with the same key.
* Generate salts, nonces, and keys using a secure random generator.
* Never hard-code passwords or encryption keys.
* Never store the master password.
* WASM is **not a secure enclave**. Secrets accessible to JavaScript should be considered accessible to the JavaScript environment.
