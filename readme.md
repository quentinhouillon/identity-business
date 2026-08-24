# Rust WASM

Ce projet contient le core Rust compilé en WebAssembly afin d'être utilisé depuis une application TypeScript / React.

Les deux projets sont **indépendants** :

- **Projet Rust** → contient le code métier et génère le WASM.
- **Projet React / TypeScript** → consomme le package WASM généré.

## Prérequis

Installer Rust :

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Installer la cible WASM :

```bash
rustup target add wasm32-unknown-unknown
```

Installer `wasm-pack` :

```bash
cargo install wasm-pack
```

## Compiler le WASM

Depuis la racine du projet Rust :

```bash
wasm-pack build crates/wasm --target web
```

Le package généré se trouve dans :

```text
crates/wasm/pkg/
```

Il contient notamment :

```text
pkg/
├── wasm.js
├── wasm_bg.wasm
├── wasm.d.ts
└── package.json
```

> Le dossier `pkg` est généré automatiquement. Il ne faut pas modifier son contenu manuellement.

## Utilisation dans React / TypeScript

Les projets Rust et React étant indépendants, il faut **récupérer le dossier `pkg` généré par le projet Rust dans le projet React**.

Par exemple :

```text
react-project/
├── src/
├── public/
├── package.json
└── wasm/
    └── pkg/
        ├── wasm.js
        ├── wasm_bg.wasm
        ├── wasm.d.ts
        └── package.json
```

Le dossier `pkg` peut être copié directement depuis le projet Rust vers le projet React.

## Initialiser le WASM

Avec une compilation `--target web`, le module WASM doit être initialisé avant d'utiliser `WasmVault` :

```typescript
import init, { WasmVault } from "./wasm/pkg/wasm";

await init();
```

## Utiliser `WasmVault`

### Créer un Vault

```typescript
const vault = new WasmVault(
    encryptedVault,
    masterPassword,
    userSalt
);
```

### Nodes

Récupérer tous les nodes :

```typescript
const nodes = vault.get_nodes();
```

Récupérer un node :

```typescript
const node = vault.get_node(nodeId);
```

Ajouter un node :

```typescript
vault.post_node(node);
```

Modifier un node :

```typescript
const updated = vault.put_node(node);
```

`put_node()` retourne `true` si le node existe et a été modifié, sinon `false`.

Supprimer un node :

```typescript
const deleted = vault.delete_node(nodeId);
```

### Edges

Récupérer tous les edges :

```typescript
const edges = vault.get_edges();
```

Récupérer un edge :

```typescript
const edge = vault.get_edge(edgeId);
```

Ajouter un edge :

```typescript
vault.post_edge(edge);
```

Modifier un edge :

```typescript
const updated = vault.put_edge(edge);
```

Supprimer un edge :

```typescript
const deleted = vault.delete_edge(edgeId);
```

## History

La `history` est accessible en lecture :

```typescript
const history = vault.get_history();
```

Les entrées de `history` sont gérées en interne par Rust.

## Security Events

Les événements de sécurité sont accessibles en lecture :

```typescript
const events = vault.get_events();
```

Les événements sont gérés en interne par Rust.

## Chiffrer le Vault

Une fois les modifications effectuées :

```typescript
const encryptedVault = vault.encrypt(
    id,
    masterPassword,
    userSalt
);
```

Pour mettre à jour un `EncryptedVault` existant :

```typescript
const encryptedVault = vault.encrypt(
    id,
    masterPassword,
    userSalt,
    previousEncryptedVault
);
```

Le résultat peut ensuite être envoyé à l'API depuis React.

## Architecture

```text
┌─────────────────────┐
│     Projet Rust     │
│                     │
│  project_core       │
│       ↓             │
│      wasm            │
│       ↓             │
│     pkg/             │
└─────────┬───────────┘
          │
          │ copier
          ↓
┌─────────────────────┐
│   Projet React/TS   │
│                     │
│     wasm/pkg/       │
│         ↓           │
│     WasmVault       │
│         ↓           │
│  Application React  │
└─────────────────────┘
```

Le code métier reste dans **Rust**. TypeScript sert uniquement de couche d'utilisation du WASM.

## Recompiler après une modification Rust

Après chaque modification du code Rust :

```bash
wasm-pack build crates/wasm --target web
```

Puis remplacer le dossier :

```text
crates/wasm/pkg/
```

dans le projet React par le nouveau `pkg` généré.