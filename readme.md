# WASM API

This package exposes Rust functionality to JavaScript and TypeScript through WebAssembly.

It provides:

- Password breach checking
- Graph traversal and SPOF detection
- Authenticated Vault data encryption
- Password-based account key derivation
- Recovery key derivation
- Vault key generation
- User identity keys (X25519 + Ed25519) with a signed user binding
- Peer identity verification, key pinning and fingerprints
- Authenticated Vault key sharing
- Identity private key encryption and decryption
- TOTP generation
- JSON import and export

## Binary Data

Binary cryptographic values exchanged between JavaScript, WASM, and Django use standard Base64.

- JavaScript passes Base64 strings to WASM.
- WASM decodes Base64 before cryptographic operations.
- WASM returns binary results as Base64 strings.
- Django may decode the values before storing them in `BinaryField`.
- Ciphertexts contain their nonce internally.
- UUIDs are passed as strings and converted to their raw 16 bytes inside WASM. Cryptographic bindings always use the raw bytes, never the text form.

The main sizes are:

| Value                           |      Size |
| ------------------------------- | --------: |
| X25519 / Ed25519 public key     |  32 bytes |
| Symmetric and derived keys      |  32 bytes |
| Ed25519 signature               |  64 bytes |
| XChaCha20 nonce                 |  24 bytes |
| Poly1305 tag                    |  16 bytes |
| Password salt                   |  32 bytes |
| Recovery key                    |  32 bytes |
| Encrypted identity blob         | 105 bytes |
| Wrapped Vault key               | 169 bytes |

## Cryptography

The cryptographic layer uses:

- XChaCha20-Poly1305 for authenticated encryption
- X25519 for key agreement
- Ed25519 for signatures (identity binding and Vault key envelopes)
- HKDF-SHA256 for key separation
- Argon2id for password-based derivation
- SHA-256 for fingerprints
- `zeroize` for sensitive key material where applicable

The current protocol version is `1`.

The Rust code is split in two modules:

- `key`: generates, derives and verifies keys. It never encrypts data.
- `crypto`: encrypts and decrypts Vault data, identity blobs and wrapped Vault keys.

## Errors

Every error thrown to JavaScript is an object `{ code, message }`.

```typescript
try {
  // ...
} catch (e) {
  if (e.code === "IDENTITY_KEY_CHANGED") {
    // warn the user
  }
}
```

| Code                     | Meaning                                                         |
| ------------------------ | --------------------------------------------------------------- |
| `INVALID_INPUT`          | Malformed Base64, UUID or wrong length (JS-side input)          |
| `INVALID_KEY`            | Key rejected by the cipher or signature verifier                |
| `ENCRYPTION_FAILED`      | Encryption failed                                               |
| `DECRYPTION_FAILED`      | Wrong key, tampered data, or wrong AAD (Vault, object, user)    |
| `KEY_DERIVATION_FAILED`  | Invalid KDF parameters or invalid X25519 shared secret          |
| `KEY_GENERATION_FAILED`  | Secure random generator failure                                 |
| `INVALID_SALT`           | Salt shorter than 32 bytes                                      |
| `UNSUPPORTED_VERSION`    | Unknown protocol version byte                                   |
| `UNSUPPORTED_MESSAGE_TYPE` | Message type not allowed for Vault data                       |
| `INVALID_SIGNATURE`      | Binding or Vault key envelope signature is invalid              |
| `IDENTITY_MISMATCH`      | Wrong `user_id`, wrong Vault, or keys differ from expected ones |
| `IDENTITY_KEY_CHANGED`   | Peer Ed25519 key differs from the pinned one                    |
| `ERROR`                  | Any other error                                                 |

`SERIALIZATION_FAILED` and `DESERIALIZATION_FAILED` are also defined for serialization errors.

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

| Constant              |  Value | Usage                 |
| --------------------- | -----: | --------------------- |
| `TYPE_NODE`           | `0x02` | Node data             |
| `TYPE_EDGE`           | `0x03` | Edge data             |
| `TYPE_HISTORY`        | `0x04` | History data          |
| `TYPE_SECURITY_EVENT` | `0x05` | Security event data   |

Any other value is rejected with `UNSUPPORTED_MESSAGE_TYPE`. Vault key wrapping and identity encryption use dedicated APIs with their own contexts.

Ciphertext format:

```text
[version: 1 byte][nonce: 24 bytes][ciphertext + Poly1305 tag]
```

## Account Keys

The password flow derives two independent keys:

- `encKey`: remains in the client and encrypts the identity private keys.
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

`authKey` may be sent as `recovery_auth_key`; the recovery `encKey` encrypts the recovery copy of the identity blob. Argon2id is not needed because the recovery key is already a random 256-bit secret.

## Vault Key

### `generate_vault_key_wasm()`

Generates a random 32-byte Vault key client-side.

```typescript
const vaultKey = generate_vault_key_wasm();
```

The Vault key encrypts nodes, edges, history, and security events. It must never be sent to Django in plaintext.

## Identity

Each user has an identity made of two key pairs:

- X25519: key agreement, used to receive Vault keys.
- Ed25519: signatures, used to prove who created a binding or a Vault key envelope.

The Ed25519 key signs a **binding** of `(user_id, x25519_public, ed25519_public)`. The server stores and distributes this binding. Clients verify it, and pin the Ed25519 key, before trusting any public key coming from the server.

### Classes

Private keys never leave WASM memory. JavaScript only holds handles.

- `Identity`: the user's private identity. Call `.free()` when done to wipe the secrets.
  - `x25519_public()`: Base64 public key.
  - `ed25519_public()`: Base64 public key.
  - `public_identity(userId)`: signed binding `{ userId, x25519Public, ed25519Public, signature }`.
- `PeerIdentity`: a remote identity that passed verification. It can only be obtained from `verify_peer_identity_wasm` or `self_peer_wasm`.
  - `user_id()`, `x25519_public()`, `ed25519_public()`.
  - `status()`: `"pinned"` or `"first_use"`.

### `generate_identity_wasm()`

Generates a new `Identity`.

```typescript
const identity = generate_identity_wasm();
const publicIdentity = identity.public_identity(userId);
```

`userId` must be known before registration (generate a UUID v4 client-side, and send it as the account `id`).

### `encrypt_identity_wasm(identity, encKey, userId)`

Encrypts both private keys with an account or recovery `encKey`. The AAD binds the blob to the user and to both public keys.

```typescript
const encryptedIdentity = encrypt_identity_wasm(identity, encKey, userId);
const recoveryIdentity = encrypt_identity_wasm(identity, recoveryKeys.encKey, userId);
```

Format:

```text
[version: 1 byte][nonce: 24 bytes][ciphertext: 64 bytes + 16-byte tag]
```

### `decrypt_identity_wasm(encKey, ownIdentity, encryptedIdentity)`

Decrypts the identity and returns an `Identity`.

```typescript
const identity = decrypt_identity_wasm(encKey, ownPublicIdentity, encryptedIdentity);
```

`ownPublicIdentity` (`{ userId, x25519Public, ed25519Public, signature }`) must come from **local storage**, not from a fresh server response. Decryption fails if the blob belongs to another user, was paired with other public keys, or does not match the expected public keys.

### `verify_peer_identity_wasm(received, expectedUserId, pinnedEd25519?)`

Verifies a public identity received from the server and returns a `PeerIdentity`.

```typescript
const peer = verify_peer_identity_wasm(
  { userId, x25519Public, ed25519Public, signature },
  recipientId,
  pinnedEd25519, // Base64 or undefined on first contact
);
```

It throws:

- `IDENTITY_MISMATCH` if the identity belongs to another user than `expectedUserId`.
- `INVALID_SIGNATURE` if the binding signature is invalid.
- `IDENTITY_KEY_CHANGED` if the Ed25519 key differs from the pinned one.

On first contact `peer.status()` is `"first_use"`: show the fingerprint, then store `peer.ed25519_public()` as the pinned key.

### `self_peer_wasm(identity, userId)`

Returns your own identity as a `PeerIdentity`, needed to wrap a Vault key for yourself (for example at Vault creation).

### `fingerprint_wasm(publicIdentity)`

Returns a fingerprint (SHA-256, hex, groups of 8 characters) covering `user_id` and the Ed25519 key. Compare it out of band (call, QR code, in person) to protect the first contact.

## Vault Key Sharing

Vault keys are encrypted for a verified recipient with an ephemeral X25519 key pair, HKDF-SHA256 and XChaCha20-Poly1305, then **signed by the sender's Ed25519 key**. The derived key and the AAD are bound to the Vault, the sender, the recipient, the ephemeral public key and the recipient public key.

### `encrypt_vault_key_wasm(sender, senderId, recipient, vaultId, vaultKey)`

```typescript
const wrapped = encrypt_vault_key_wasm(
  identity,   // Identity
  myUserId,
  peer,       // PeerIdentity
  vaultId,
  vaultKey,
);
```

Store the result with `vault_id`, `sender_id` and `recipient_id` (a unique `(vault, recipient)` pair).

Format:

```text
[version: 1 byte]
[ephemeral public key: 32 bytes]
[nonce: 24 bytes]
[signature: 64 bytes]
[ciphertext: 32-byte Vault key + 16-byte tag]
```

### `decrypt_vault_key_wasm(recipient, recipientId, sender, vaultId, wrappedVaultKey)`

```typescript
const vaultKey = decrypt_vault_key_wasm(
  identity,     // Identity
  myUserId,
  senderPeer,   // PeerIdentity of the sender, verified beforehand
  vaultId,
  wrapped,
);
```

The signature is verified before decryption. Any change to the envelope, the Vault, the sender or the recipient makes it fail.

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

## Flows

### Registration

```typescript
const userId = crypto.randomUUID();
const salt = generate_salt_wasm();
const params = default_kdf_params_wasm();
const keys = derive_account_keys_wasm(password.normalize("NFKC"), salt, params.memoryKib, params.iterations, params.lanes);

const recoveryKey = generate_recovery_key_wasm(); // show once
const recoveryKeys = derive_recovery_keys_wasm(recoveryKey);

const identity = generate_identity_wasm();
const publicIdentity = identity.public_identity(userId);

// Send: userId, keys.authKey, recoveryKeys.authKey, salt, params,
// publicIdentity (x25519Public, ed25519Public, signature),
// encrypt_identity_wasm(identity, keys.encKey, userId),
// encrypt_identity_wasm(identity, recoveryKeys.encKey, userId)
// Keep publicIdentity locally.
```

### Login

```typescript
const identity = decrypt_identity_wasm(encKey, ownPublicIdentity, encryptedIdentity);
```

### Sharing a Vault

```typescript
const peer = verify_peer_identity_wasm(identityFromServer, recipientId, pinnedEd25519);
if (peer.status() === "first_use") {
  // show fingerprint_wasm(identityFromServer), then pin peer.ed25519_public()
}
const wrapped = encrypt_vault_key_wasm(identity, myUserId, peer, vaultId, vaultKey);
```

### Receiving a Vault

```typescript
const senderPeer = verify_peer_identity_wasm(senderIdentityFromServer, senderId, pinnedSenderEd25519);
const vaultKey = decrypt_vault_key_wasm(identity, myUserId, senderPeer, vaultId, wrapped);
```

## Django Integration

Django may store public and encrypted protocol values, but should never receive:

- The plaintext password
- The Argon2 root key
- `encKey`
- The plaintext X25519 or Ed25519 private keys
- The plaintext Vault key
- Plaintext Vault objects

Django may store:

- `authKey` and `recovery_auth_key` according to the authentication protocol
- X25519 and Ed25519 public keys
- The binding signature (`key_binding_signature`)
- Password salts and KDF parameters
- Encrypted identity blobs (password and recovery copies, 105 bytes each)
- Wrapped Vault keys (169 bytes) with `vault_id`, `sender_id`, `recipient_id`
- Ciphertexts and object metadata

Server-side rules:

- The account `id` is chosen by the client, since the binding signature depends on it.
- Public keys and the binding are immutable after registration, including during password change or reset.
- Expose identities through an endpoint addressed by user `id`, and let the client verify them with `verify_peer_identity_wasm`.
- The server may verify the binding signature at registration as defense in depth, but clients must never rely on that check.

Field names returned by Django are snake_case (`id`, `public_key`, `ed25519_public_key`, `key_binding_signature`). Convert them to `{ userId, x25519Public, ed25519Public, signature }` before calling WASM.

## Security Notes

- Generate keys, salts, and nonces with a cryptographically secure random generator.
- Never reuse a nonce with the same encryption key.
- Never hard-code passwords or encryption keys.
- Never log private keys, `encKey`, `authKey`, recovery keys, or plaintext passwords.
- Verify ciphertext authentication before using plaintext.
- Bind ciphertexts to their Vault and object identifiers through AAD.
- Reject unsupported protocol versions.
- Always verify identities received from the server with `verify_peer_identity_wasm` before sharing or accepting a Vault key. Pin the Ed25519 key after first contact.
- Trust on first use does not protect the very first contact against a malicious server. Compare fingerprints out of band for sensitive sharing.
- There is no key rotation or revocation yet: a changed Ed25519 key always raises `IDENTITY_KEY_CHANGED` and needs an explicit re-approval flow in the UI.
- When a peer is addressed by username, the server maps it to a user `id`. Only fingerprint comparison protects against a wrong mapping.
- Call `.free()` on `Identity` objects when they are no longer needed.
- WASM is not a secure enclave. A malicious server can replace the JavaScript/WASM application delivered to a browser.