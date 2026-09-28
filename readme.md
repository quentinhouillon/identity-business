# WASM API

This package exposes Rust functionality to JavaScript/TypeScript through WebAssembly.

It provides:

- Password breach checking
- Graph operations
- Encryption and decryption
- Master key derivation
- Vault key generation
- TOTP code generation

## Binary data transport

All binary cryptographic data exchanged with Django is represented as a
Base64 string:

- JavaScript passes Django's Base64 strings directly to WASM.
- WASM decodes Base64 strings internally before cryptographic operations.
- WASM returns binary values as Base64 strings.
- Django stores the returned Base64 strings in its `BinaryField` values.

The expected decoded sizes are 32 bytes for keys, 24 bytes for nonces, and
32 bytes for Ed25519 public and private keys.

---

# Password Security

## `check_passwords_wasm`

Checks passwords against the Have I Been Pwned service.

```typescript
const results = await check_passwords_wasm(["password123", "my-password"]);
```

### Parameters

| Parameter   | Type       | Description        |
| ----------- | ---------- | ------------------ |
| `passwords` | `string[]` | Passwords to check |

### Returns

```typescript
Promise<any>;
```

Returns the results from the password breach check.

---

# Graph

## `dfs_wasm`

Runs a Depth-First Search (DFS) on a graph.

```typescript
const visited = dfs_wasm(JSON.stringify(edges), startId);
```

### Parameters

| Parameter   | Type     | Description         |
| ----------- | -------- | ------------------- |
| `edgesJson` | `string` | Graph edges as JSON |
| `startId`   | `string` | Starting node UUID  |

### Returns

```typescript
Set<string>;
```

A set containing the visited node IDs.

---

## `spof_wasm`

Finds Single Points of Failure (SPOF) in a graph.

```typescript
const spofs = spof_wasm(JSON.stringify(edges), startId);
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

- 32-byte keys
- 24-byte nonces
- AEAD encryption
- Argon2id for password-based key derivation

## `encrypt_wasm`

Encrypts a JSON-compatible JavaScript value.

```typescript
const encrypted = encrypt_wasm(keyBase64, nonceBase64, dataBase64);
```

### Parameters

| Parameter | Type     | Description                                      |
| --------- | -------- | ------------------------------------------------ |
| `key`     | `string` | Base64-encoded encryption key (32 decoded bytes) |
| `nonce`   | `string` | Base64-encoded nonce (24 decoded bytes)          |
| `value`   | `string` | Base64-encoded plaintext data                    |

Returns the encrypted data as a Base64 string.

A **new nonce must be used for every encryption with the same key**.

The nonce does not need to be secret.

---

## `decrypt_wasm`

Decrypts data previously encrypted with `encrypt_wasm`.

```typescript
const decryptedBase64 = decrypt_wasm(keyBase64, nonceBase64, encryptedBase64);
```

### Parameters

| Parameter | Type     | Description                                      |
| --------- | -------- | ------------------------------------------------ |
| `key`     | `string` | Base64-encoded encryption key (32 decoded bytes) |
| `nonce`   | `string` | Base64-encoded nonce (24 decoded bytes)          |
| `value`   | `string` | Base64-encoded encrypted data                    |

The same key and nonce used for encryption must be provided.
Returns the decrypted data as a Base64 string.

---

# Key Management

## `derive_master_key_wasm`

Derives a 32-byte master key from a password using Argon2id.

```typescript
const masterKeyBase64 = derive_master_key_wasm(passwordBase64, saltBase64);
```

### Parameters

| Parameter        | Type     | Description                   |
| ---------------- | -------- | ----------------------------- |
| `masterPassword` | `string` | Base64-encoded password bytes |
| `salt`           | `string` | Base64-encoded random salt    |

### Returns

```typescript
string;
```

A Base64-encoded 32-byte master key, ready to send to Django.

The salt is not secret and can be stored with the encrypted data.

---

## `generate_vault_key_wasm`

Generates a random 32-byte vault key.

```typescript
const vaultKey = generate_vault_key_wasm();
```

### Returns

```typescript
string;
```

A Base64-encoded cryptographically secure 32-byte key, ready to store in a
Django `BinaryField`.

---

## `generate_asymmetric_keypair_wasm`

Generates an Ed25519 asymmetric key pair.

```typescript
const keypair = generate_asymmetric_keypair_wasm();

const privateKey = keypair.privateKey;
const publicKey = keypair.publicKey;
```

### Returns

```typescript
{
  privateKey: string;
  publicKey: string;
}
```

Both keys contain 32 bytes. The private key must remain secret; the public key
can be shared. Both values are Base64 strings ready to send to Django. The
private key should be encrypted with the master key before storage.

---

# TOTP

## `get_totp_code`

Generates a TOTP code for a node.

```typescript
const code = get_totp_code(node, timestamp);
```

### Parameters

| Parameter   | Type     | Description                            |
| ----------- | -------- | -------------------------------------- |
| `node`      | `Node`   | Node containing the TOTP configuration |
| `timestamp` | `number` | Unix timestamp                         |

### Returns

```typescript
string;
```

The generated TOTP code.

### Example

```typescript
const code = get_totp_code(node, Math.floor(Date.now() / 1000));

console.log(code);
```

---

# Security Notes

- Use **32-byte keys**.
- Use **24-byte nonces**.
- Never reuse a nonce with the same key.
- Generate salts, nonces, and keys using a secure random generator.
- Never hard-code passwords or encryption keys.
- Never store the master password.
- WASM is **not a secure enclave**. Secrets accessible to JavaScript should be considered accessible to the JavaScript environment.
