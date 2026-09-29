# WASM API

This package exposes Rust functionality to JavaScript/TypeScript through WebAssembly.

It provides:

- Password breach checking
- Graph operations
- Symmetric encryption and decryption
- Master key derivation with Argon2id
- Vault key generation
- X25519 key pair generation
- Vault key wrapping and unwrapping
- Private key encryption and decryption
- TOTP code generation
- JSON import/export

---

# Binary Data Transport

All binary cryptographic data exchanged between JavaScript, WASM, and Django is represented as a Base64 string.

The general flow is:

```text
JavaScript
    │
    │ Base64
    ▼
WASM
    │
    │ Decode Base64
    ▼
Rust cryptographic functions
    │
    │ Binary data
    ▼
WASM
    │
    │ Base64
    ▼
JavaScript
    │
    │ Base64
    ▼
Django
    │
    │ BinaryField
    ▼
Database
```

Rules:

- JavaScript passes Base64 strings to WASM.
- WASM decodes Base64 internally.
- Cryptographic operations operate on raw binary data.
- WASM returns binary results as Base64 strings.
- Django can decode the Base64 value before storing it in a `BinaryField`, or use the decoded binary representation directly.
- Binary ciphertexts include their nonce internally where applicable.

The main cryptographic sizes are:

| Value | Size |
|---|---:|
| Symmetric key | 32 bytes |
| X25519 private key | 32 bytes |
| X25519 public key | 32 bytes |
| XChaCha20 nonce | 24 bytes |
| Poly1305 authentication tag | 16 bytes |
| Argon2id output | 32 bytes |
| Password salt | 16 bytes or more |

Base64 encoding does not change the underlying binary size requirements.

---

# Password Security

## `check_passwords_wasm`

Checks passwords against the Have I Been Pwned service.

```typescript
const results = await check_passwords_wasm([
  "password123",
  "my-password",
]);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
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
const visited = dfs_wasm(
  JSON.stringify(edges),
  startId
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `edgesJson` | `string` | Graph edges encoded as JSON |
| `startId` | `string` | Starting node UUID |

### Returns

```typescript
Set<string>;
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

| Parameter | Type | Description |
|---|---|---|
| `edgesJson` | `string` | Graph edges encoded as JSON |
| `startId` | `string` | Starting node UUID |

### Returns

```typescript
string[];
```

An array containing the SPOF node IDs.

---

# Cryptography

The cryptographic layer uses:

- XChaCha20-Poly1305 for authenticated symmetric encryption
- X25519 for key agreement
- HKDF-SHA256 for deriving encryption keys from X25519 shared secrets
- Argon2id for password-based key derivation
- 32-byte cryptographic keys
- 24-byte XChaCha20 nonces
- 16-byte Poly1305 authentication tags

The protocol uses a versioned binary format.

---

# Symmetric Encryption

## `encrypt_wasm`

Encrypts arbitrary binary data using a Vault key.

The nonce is generated internally by Rust.

The caller does **not** provide a nonce.

```typescript
const encrypted = encrypt_wasm(
  vaultKeyBase64,
  messageType,
  vaultId,
  objectId,
  plaintextBase64
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `key` | `string` | Base64-encoded 32-byte encryption key |
| `messageType` | `number` | Protocol message type |
| `vaultId` | `string` | Vault UUID |
| `objectId` | `string` | Object UUID |
| `value` | `string` | Base64-encoded plaintext |

### Message Types

The current protocol defines:

| Constant | Value | Usage |
|---|---:|---|
| `TYPE_VAULT_KEY_WRAP` | `0x01` | Vault key wrapping |
| `TYPE_NODE` | `0x02` | Node data |
| `TYPE_EDGE` | `0x03` | Edge data |
| `TYPE_HISTORY` | `0x04` | History data |
| `TYPE_SECURITY_EVENT` | `0x05` | Security event data |
| `PRIVATE_KEY_TYPE` | `0x06` | User private key |

`TYPE_VAULT_KEY_WRAP` and `PRIVATE_KEY_TYPE` must not be passed to `encrypt_wasm`. They have dedicated APIs.

### Returns

```typescript
string;
```

A Base64-encoded ciphertext.

The encrypted binary format is:

```text
+----------------+----------------+-------------------------+
| Version        | Nonce          | Ciphertext + Tag        |
| 1 byte         | 24 bytes       | Variable                |
+----------------+----------------+-------------------------+
```

The nonce is included in the ciphertext and does not need to be stored separately.

---

## `decrypt_wasm`

Decrypts data previously encrypted with `encrypt_wasm`.

```typescript
const decryptedBase64 = decrypt_wasm(
  vaultKeyBase64,
  messageType,
  vaultId,
  objectId,
  encryptedBase64
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `key` | `string` | Base64-encoded 32-byte encryption key |
| `messageType` | `number` | Expected protocol message type |
| `vaultId` | `string` | Vault UUID |
| `objectId` | `string` | Object UUID |
| `value` | `string` | Base64-encoded ciphertext |

### Returns

```typescript
string;
```

A Base64-encoded plaintext.

The `messageType`, `vaultId`, and `objectId` must match the values used during encryption.

---

# Authenticated Additional Data

The encryption API uses Additional Authenticated Data (AAD).

The AAD contains:

```text
Protocol name
Protocol version
Message type
Vault ID
Object ID
```

The AAD is authenticated but not encrypted.

Conceptually:

```text
AAD
 │
 ├── MYAPP-VAULT
 ├── Protocol version
 ├── Message type
 ├── Vault ID
 └── Object ID
```

This prevents a valid ciphertext from being transparently moved between different objects or message types.

For example, a ciphertext encrypted as a `TYPE_NODE` cannot be successfully decrypted as a `TYPE_EDGE`.

---

# Master Key Derivation

## `derive_master_key_wasm`

Derives a 32-byte master key from a password using Argon2id.

```typescript
const masterKeyBase64 = derive_master_key_wasm(
  passwordBase64,
  saltBase64
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `masterPassword` | `string` | Base64-encoded password bytes |
| `salt` | `string` | Base64-encoded random salt |

### Returns

```typescript
string;
```

A Base64-encoded 32-byte master key.

The current Argon2id configuration is:

```text
Algorithm:  Argon2id
Memory:     64 MiB
Iterations: 3
Lanes:      1
Output:     32 bytes
```

The salt is not secret and may be stored alongside the encrypted private key.

The master key is intended to protect the user's X25519 private key. It is not the Vault key.

---

# Vault Key

## `generate_vault_key_wasm`

Generates a cryptographically secure random 32-byte Vault key.

```typescript
const vaultKey = generate_vault_key_wasm();
```

### Returns

```typescript
string;
```

A Base64-encoded 32-byte Vault key.

The Vault key is generated client-side and should never be sent to Django in plaintext.

It is used to encrypt Vault data such as:

- Nodes
- Edges
- History
- Security events

---

# X25519 Key Pair

## `generate_asymmetric_keypair_wasm`

Generates an X25519 key pair.

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

Both values are Base64-encoded 32-byte values.

The private key must remain client-side.

The public key may be sent to Django and stored in the user's public key field.

> This key pair is X25519, not Ed25519. X25519 is used for key agreement and Vault key wrapping.

---

# Vault Key Wrapping

The Vault key must be encrypted separately for each Vault member.

The backend should never receive the plaintext Vault key.

## `encrypt_vault_key_wasm`

Encrypts a Vault key for a specific user's X25519 public key.

```typescript
const encryptedVaultKey = encrypt_vault_key_wasm(
  recipientPublicKey,
  vaultId,
  userId,
  vaultKey
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `recipientPublicKey` | `string` | Base64-encoded 32-byte X25519 public key |
| `vaultId` | `string` | Vault UUID |
| `userId` | `string` | Recipient user UUID |
| `vaultKey` | `string` | Base64-encoded 32-byte Vault key |

Internally:

```text
Recipient X25519 public key
          │
          ▼
   Ephemeral X25519 key pair
          │
          ▼
   X25519 shared secret
          │
          ▼
      HKDF-SHA256
          │
          ▼
   32-byte encryption key
          │
          ▼
 XChaCha20-Poly1305
          │
          ▼
 Encrypted Vault key
```

### Returns

```typescript
string;
```

A Base64-encoded wrapped Vault key.

The binary format is:

```text
+---------+----------------------+----------------+----------------------+
| Version | Ephemeral public key | Nonce          | Ciphertext + Tag     |
| 1 byte  | 32 bytes             | 24 bytes       | 48 bytes             |
+---------+----------------------+----------------+----------------------+
```

The 48-byte ciphertext consists of:

```text
32-byte Vault key
+
16-byte Poly1305 tag
```

The backend stores this value as the user's `encrypted_vault_key`.

---

## `decrypt_vault_key_wasm`

Decrypts a Vault key using the recipient's X25519 private key.

```typescript
const vaultKey = decrypt_vault_key_wasm(
  privateKey,
  vaultId,
  userId,
  encryptedVaultKey
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `privateKey` | `string` | Base64-encoded 32-byte X25519 private key |
| `vaultId` | `string` | Vault UUID |
| `userId` | `string` | User UUID |
| `encryptedVaultKey` | `string` | Base64-encoded wrapped Vault key |

### Returns

```typescript
string;
```

A Base64-encoded 32-byte Vault key.

---

# Private Key Protection

The user's X25519 private key must not be stored in plaintext.

The password-derived master key is used to encrypt it locally.

```text
User password
     │
     ▼
   Argon2id
     │
     ▼
 Master key
     │
     ▼
XChaCha20-Poly1305
     │
     ▼
Encrypted X25519 private key
```

## `encrypt_private_key_wasm`

Encrypts the user's X25519 private key.

```typescript
const encryptedPrivateKey = encrypt_private_key_wasm(
  masterKey,
  userId,
  privateKey
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `masterKey` | `string` | Base64-encoded 32-byte master key |
| `userId` | `string` | User UUID |
| `privateKey` | `string` | Base64-encoded 32-byte X25519 private key |

### Returns

```typescript
string;
```

A Base64-encoded encrypted private key.

The binary format is:

```text
+---------+----------------+----------------------+
| Version | Nonce          | Ciphertext + Tag     |
| 1 byte  | 24 bytes       | 48 bytes             |
+---------+----------------+----------------------+
```

The resulting value can be stored in Django's `BinaryField`.

---

## `decrypt_private_key_wasm`

Decrypts the user's X25519 private key.

```typescript
const privateKey = decrypt_private_key_wasm(
  masterKey,
  userId,
  encryptedPrivateKey
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `masterKey` | `string` | Base64-encoded 32-byte master key |
| `userId` | `string` | User UUID |
| `encryptedPrivateKey` | `string` | Base64-encoded encrypted private key |

### Returns

```typescript
string;
```

A Base64-encoded 32-byte X25519 private key.

---

# TOTP

## `get_totp_code`

Generates a TOTP code for a node.

```typescript
const code = get_totp_code(
  node,
  Math.floor(Date.now() / 1000)
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `node` | `Node` | Node containing the TOTP configuration |
| `timestamp` | `number` | Unix timestamp in seconds |

### Returns

```typescript
string;
```

The generated TOTP code.

---

# JSON Import / Export

## `export_json`

Exports Vault data using the project's JSON export implementation.

```typescript
const data = export_json(
  vault,
  nodes,
  edges,
  history
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `vault` | `Vault` | Vault object |
| `nodes` | `Node[]` | Vault nodes |
| `edges` | `Edge[]` | Vault edges |
| `history` | `History[]` | Vault history |

### Returns

```typescript
string;
```

A Base64-encoded export payload.

---

## `import_json`

Imports a previously exported JSON payload.

```typescript
const bundle = import_json(
  dataBase64
);
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `data` | `string` | Base64-encoded export data |

### Returns

The imported bundle converted to a JavaScript value.

---

# Django Integration

The backend stores encrypted binary values but does not need access to plaintext Vault data.

A typical Vault data flow is:

```text
                    CLIENT
                      │
             Generate Vault key
                      │
                      ▼
              ┌──────────────┐
              │   Vault Key  │
              └──────┬───────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Encrypt     Encrypt    Encrypt
        Node        Edge       History
          │          │          │
          └──────────┼──────────┘
                     │
                     ▼
                   Django
                     │
                     ▼
                 BinaryField
```

For multiple Vault members:

```text
                    Vault Key
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
      User A         User B         User C
      X25519         X25519         X25519
      public         public         public
          │             │             │
          ▼             ▼             ▼
       Wrapped        Wrapped        Wrapped
       Vault Key      Vault Key      Vault Key
```

Django stores the wrapped Vault key for each member.

Django must never receive:

- The plaintext Vault key
- The plaintext X25519 private key
- The master key
- The user's password
- Plaintext encrypted Vault objects

Django may store:

- X25519 public keys
- Password salts
- Encrypted private keys
- Wrapped Vault keys
- Ciphertexts
- Vault/member metadata
- Roles and permissions
- Object IDs
- Timestamps

---

# Ciphertext Format

Symmetric Vault data uses:

```text
[version][nonce][ciphertext + authentication tag]
```

For XChaCha20-Poly1305:

```text
Version          1 byte
Nonce           24 bytes
Ciphertext       N bytes
Poly1305 tag    16 bytes
```

The nonce is generated randomly for every encryption operation.

The nonce is **not secret** and is stored directly inside the ciphertext.

There is therefore no separate nonce field required in the Django model.

For example:

```text
ciphertext
│
├── version
├── nonce
└── ciphertext + authentication tag
```

---

# Security Notes

- Use 32-byte cryptographic keys.
- Use XChaCha20-Poly1305 for authenticated symmetric encryption.
- Never reuse a nonce with the same encryption key.
- Generate keys, salts, and nonces using a cryptographically secure random generator.
- Never hard-code passwords or encryption keys.
- Never store the master password.
- Never send the Vault key to Django in plaintext.
- Never send the X25519 private key to Django in plaintext.
- Encrypt the X25519 private key before storing it.
- Use a unique random salt for each user's password-derived key.
- Keep the Vault key client-side whenever possible.
- Treat ciphertext as untrusted input and always verify authentication before using plaintext.
- Bind ciphertexts to their Vault and object identifiers through AAD.
- Do not reuse an encrypted value under a different object ID or message type.
- Do not silently accept unsupported protocol versions.
- Do not manually provide nonces to the WASM API.
- The nonce is generated internally by Rust.

## Browser Security

WASM is **not a secure enclave**.

Any secret accessible to JavaScript should be considered accessible to the JavaScript environment.

Client-side encryption protects data from a backend that only sees the encrypted protocol data. It does not by itself protect against a server that can replace the JavaScript/WASM application delivered to the browser.

For stronger protection against a malicious application server, additional mechanisms such as authenticated key distribution and trusted/signed client delivery are required.

---

# Protocol Versioning

The current protocol version is:

```text
1
```

Ciphertexts contain the protocol version as their first byte.

Unsupported versions must be rejected rather than interpreted using the current protocol.

Changing the cryptographic format should result in a new protocol version rather than silently changing the meaning of existing ciphertexts.

---