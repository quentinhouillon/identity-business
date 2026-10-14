# WASM API

This package exposes Rust functionality to JavaScript and TypeScript through WebAssembly.

It provides:

- Password breach checking
- Graph traversal and SPOF detection
- Authenticated Vault data encryption
- Password-based account key derivation
- Recovery key derivation
- Vault key generation and wrapping
- X25519 key pair generation
- Private key encryption and decryption
- TOTP generation
- JSON import and export

## Binary Data

Binary cryptographic values exchanged between JavaScript, WASM, and Django use standard Base64.

- JavaScript passes Base64 strings to WASM.
- WASM decodes Base64 before cryptographic operations.
- WASM returns binary results as Base64 strings.
- Django may decode the values before storing them in `BinaryField`.
- Ciphertexts contain their nonce internally.

The main sizes are:

| Value                      |     Size |
| -------------------------- | -------: |
| X25519 private/public key  | 32 bytes |
| Symmetric and derived keys | 32 bytes |
| XChaCha20 nonce            | 24 bytes |
| Poly1305 tag               | 16 bytes |
| Password salt              | 32 bytes |
| Recovery key               | 32 bytes |

## Cryptography

The cryptographic layer uses:

- XChaCha20-Poly1305 for authenticated encryption
- X25519 for key agreement
- HKDF-SHA256 for key separation
- Argon2id for password-based derivation
- `zeroize` for sensitive derived key material where applicable

The current protocol version is `1`.

## Password Breach Check

### `check_passwords_wasm(passwords)`

Checks passwords against the Have I Been Pwned service.

```typescript
const results = await check_passwords_wasm(["password123"]);
```

## Graph

### `dfs_wasm(edgesJson, startId)`

Runs depth-first search and returns a `Set<string>` through `JsValue`.

```typescript
const visited = dfs_wasm(JSON.stringify(edges), startId);
```

### `spof_wasm(edgesJson, startId)`

Finds single points of failure and returns an array of UUID strings.

```typescript
const spofs = spof_wasm(JSON.stringify(edges), startId);
```

Both functions expect valid edge JSON and UUID strings.

## Vault Data Encryption

### `encrypt_wasm(key, messageType, vaultId, objectId, value)`

Encrypts Base64-encoded data with a Base64-encoded 32-byte Vault key. The nonce is generated internally and must not be supplied by the caller.

```typescript
const ciphertext = encrypt_wasm(
  vaultKeyBase64,
  0x02,
  vaultId,
  nodeId,
  plaintextBase64,
);
```

### `decrypt_wasm(key, messageType, vaultId, objectId, value)`

Decrypts a ciphertext previously produced by `encrypt_wasm`.

```typescript
const plaintext = decrypt_wasm(
  vaultKeyBase64,
  0x02,
  vaultId,
  nodeId,
  ciphertextBase64,
);
```

`vaultId`, `objectId`, and `messageType` are authenticated through AAD and must match during decryption.

Supported message types:

| Constant              |  Value | Usage                             |
| --------------------- | -----: | --------------------------------- |
| `TYPE_VAULT_KEY_WRAP` | `0x01` | Vault key wrapping, dedicated API |
| `TYPE_NODE`           | `0x02` | Node data                         |
| `TYPE_EDGE`           | `0x03` | Edge data                         |
| `TYPE_HISTORY`        | `0x04` | History data                      |
| `TYPE_SECURITY_EVENT` | `0x05` | Security event data               |
| `PRIVATE_KEY_TYPE`    | `0x06` | Private key, dedicated API        |

`0x01` and `0x06` must not be passed to `encrypt_wasm` or `decrypt_wasm`.

Ciphertext format:

```text
[version: 1 byte][nonce: 24 bytes][ciphertext + Poly1305 tag]
```

## Account Keys

The password flow derives two independent keys:

- `encKey`: remains in the client and encrypts the X25519 private key.
- `authKey`: may be sent to the backend for authentication.

The backend must never receive the password, the Argon2 root key, or `encKey`.

### `generate_salt_wasm()`

Generates a random 32-byte salt for registration or password changes.

```typescript
const saltBase64 = generate_salt_wasm();
```

The salt is not secret and must be stored with the account.

### `default_kdf_params_wasm()`

Returns the default Argon2id parameters:

```typescript
const params = default_kdf_params_wasm();
// { memoryKib: 131072, iterations: 4, lanes: 2 }
```

Server-provided values are validated by WASM. Accepted ranges are:

- Memory: 64 to 512 MiB
- Iterations: 2 to 10
- Lanes: 1 to 4

### `derive_account_keys_wasm(password, salt, memoryKib, iterations, lanes)`

Derives `{ encKey, authKey }` from a normalized password, a Base64 salt, and Argon2id parameters. The password is plain text, not Base64; normalize it with NFKC before calling WASM.

```typescript
const keys = derive_account_keys_wasm(
  password.normalize("NFKC"),
  saltBase64,
  params.memoryKib,
  params.iterations,
  params.lanes,
);
// { encKey: string, authKey: string }
```

Argon2id derives a 32-byte root key. HKDF-SHA256 then derives independent `encKey` and `authKey` values using separate contexts. Because Argon2id is deliberately expensive, call this function from a Web Worker in a browser.

## Recovery Key

### `generate_recovery_key_wasm()`

Generates a random 32-byte recovery key. Display it once to the user and never send the plaintext value to the backend.

```typescript
const recoveryKey = generate_recovery_key_wasm();
```

### `derive_recovery_keys_wasm(recoveryKey)`

Derives `{ encKey, authKey }` from the recovery key using HKDF-SHA256.

```typescript
const recoveryKeys = derive_recovery_keys_wasm(recoveryKey);
```

`authKey` may be sent as `recovery_auth_key`; the recovery `encKey` encrypts the recovery copy of the private key. Argon2id is not needed because the recovery key is already a random 256-bit secret.

## Vault Key

### `generate_vault_key_wasm()`

Generates a random 32-byte Vault key client-side.

```typescript
const vaultKey = generate_vault_key_wasm();
```

The Vault key encrypts nodes, edges, history, and security events. It must never be sent to Django in plaintext.

## X25519 Key Pair

### `generate_asymmetric_keypair_wasm()`

Generates an X25519 key pair. Both values are Base64-encoded 32-byte values.

```typescript
const keyPair = generate_asymmetric_keypair_wasm();
const privateKey = keyPair.privateKey;
const publicKey = keyPair.publicKey;
```

The private key remains client-side. The public key may be stored by Django. X25519 is used for key agreement, not signatures; it is not Ed25519.

## Vault Key Wrapping

### `encrypt_vault_key_wasm(recipientPublicKey, vaultId, userId, vaultKey)`

Encrypts a Vault key for a recipient's X25519 public key using an ephemeral X25519 key pair, HKDF-SHA256, and XChaCha20-Poly1305.

```typescript
const encryptedVaultKey = encrypt_vault_key_wasm(
  recipientPublicKey,
  vaultId,
  userId,
  vaultKey,
);
```

The wrapped format is:

```text
[version: 1 byte]
[ephemeral public key: 32 bytes]
[nonce: 24 bytes]
[ciphertext: 32-byte Vault key + 16-byte tag]
```

### `decrypt_vault_key_wasm(privateKey, vaultId, userId, encryptedVaultKey)`

Decrypts a wrapped Vault key with the recipient's X25519 private key.

```typescript
const vaultKey = decrypt_vault_key_wasm(
  privateKey,
  vaultId,
  userId,
  encryptedVaultKey,
);
```

## Private Key Protection

### `encrypt_private_key_wasm(encKey, privateKey)`

Encrypts the user's X25519 private key locally with an account or recovery `encKey`.

```typescript
const encryptedPrivateKey = encrypt_private_key_wasm(encKey, privateKey);
```

### `decrypt_private_key_wasm(encKey, encryptedPrivateKey)`

Decrypts the private key locally.

```typescript
const privateKey = decrypt_private_key_wasm(encKey, encryptedPrivateKey);
```

The encrypted format is:

```text
[version: 1 byte][nonce: 24 bytes][ciphertext: 32 bytes + 16-byte tag]
```

The encrypted value may be stored in Django, but the plaintext private key, `encKey`, and password must never be sent to the backend.

## TOTP

### `get_totp_code(node, timestamp)`

Generates a TOTP code from a `Node` value and a Unix timestamp in seconds.

```typescript
const code = get_totp_code(node, Math.floor(Date.now() / 1000));
```

## JSON Import and Export

### `export_json(vault, nodes, edges, history)`

Serializes a Vault bundle and returns a Base64-encoded payload.

```typescript
const data = export_json(vault, nodes, edges, history);
```

### `import_json(data)`

Decodes a Base64 export payload and returns the imported bundle.

```typescript
const bundle = import_json(dataBase64);
```

## Django Integration

Django may store public and encrypted protocol values, but should never receive:

- The plaintext password
- The Argon2 root key
- `encKey`
- The plaintext X25519 private key
- The plaintext Vault key
- Plaintext Vault objects

Django may store:

- `authKey` and `recovery_auth_key` according to the authentication protocol
- X25519 public keys
- Password salts and KDF parameters
- Encrypted private keys
- Wrapped Vault keys
- Ciphertexts and object metadata

## Security Notes

- Generate keys, salts, and nonces with a cryptographically secure random generator.
- Never reuse a nonce with the same encryption key.
- Never hard-code passwords or encryption keys.
- Never log `privateKey`, `encKey`, `authKey`, recovery keys, or plaintext passwords.
- Verify ciphertext authentication before using plaintext.
- Bind ciphertexts to their Vault and object identifiers through AAD.
- Reject unsupported protocol versions.
- Authenticate or otherwise protect public-key registration; X25519 alone does not provide sender authentication.
- WASM is not a secure enclave. A malicious server can replace the JavaScript/WASM application delivered to a browser.
