# Rust WASM

Ce projet contient le core Rust compilé en WebAssembly afin d'être utilisé depuis une application TypeScript / React.

Les deux projets sont **indépendants** :

- **Projet Rust** → contient le code métier et génère le WASM.
- **Projet React / TypeScript** → consomme le package WASM généré.

Le WASM fait le lien entre le frontend et le backend :

```text
React / TypeScript
        ↓
      WASM
        ↓
   Rust Core
        ↓
    API Backend
```

Le backend ne reçoit et ne renvoie que des **données chiffrées**. Le chiffrement et le déchiffrement sont réalisés côté Rust.

---

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

---

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

---

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

---

## Initialiser le WASM

Avec une compilation `--target web`, le module WASM doit être initialisé avant d'utiliser `WasmVault` :

```typescript
import init, {
    WasmVault,
    set_base_url
} from "./wasm/pkg/wasm";

await init();
```

---

## Configurer l'API Backend

L'URL du backend doit être configurée avant de créer le Vault :

```typescript
set_base_url("https://api.example.com");
```

Cette URL est utilisée par `ApiService` côté Rust pour communiquer avec le backend.

---

# WasmVault

## Créer un Vault

La création du Vault est **asynchrone**.

```typescript
const vault = await new WasmVault(
    userId,
    masterPassword,
    userSalt,
    token
);
```

### Paramètres

| Paramètre | Type | Description |
|---|---|---|
| `userId` | `string` | UUID de l'utilisateur |
| `masterPassword` | `string` | Mot de passe maître |
| `userSalt` | `Uint8Array` | Salt utilisateur |
| `token` | `string \| undefined` | Token d'authentification |

Exemple :

```typescript
const vault = await new WasmVault(
    "550e8400-e29b-41d4-a716-446655440000",
    masterPassword,
    userSalt,
    accessToken
);
```

Lors de la création, Rust :

1. dérive la clé maître ;
2. contacte le backend ;
3. récupère les données chiffrées ;
4. déchiffre les données ;
5. construit le `Vault` en mémoire.

---

## Récupérer le Vault

```typescript
const data = vault.get_vault();
```

Le Vault contient :

```typescript
{
    nodes,
    edges,
    history,
    events
}
```

Les données retournées sont déchiffrées et peuvent être utilisées directement par TypeScript.

---

# Nodes

## Récupérer tous les nodes

```typescript
const nodes = vault.get_nodes();
```

## Récupérer un node

```typescript
const node = vault.get_node(nodeId);
```

L'ID doit être un UUID sous forme de `string`.

## Ajouter un node

```typescript
await vault.post_node(
    node,
    token
);
```

Rust :

1. reçoit le node en clair depuis TypeScript ;
2. chiffre le node ;
3. l'envoie au backend ;
4. met à jour le Vault local.

## Modifier un node

```typescript
await vault.put_node(
    node,
    token
);
```

Rust :

1. récupère l'ancien node ;
2. compare l'ancien et le nouveau ;
3. génère automatiquement les entrées `History` ;
4. chiffre le node ;
5. envoie le node chiffré au backend ;
6. chiffre et envoie les entrées d'historique ;
7. met à jour le Vault local.

## Supprimer un node

```typescript
await vault.delete_node(
    nodeId,
    token
);
```

Rust :

1. supprime le node du backend ;
2. crée automatiquement l'entrée `History` ;
3. chiffre l'historique ;
4. l'envoie au backend ;
5. supprime le node du Vault local.

---

# Edges

## Récupérer tous les edges

```typescript
const edges = vault.get_edges();
```

## Récupérer un edge

```typescript
const edge = vault.get_edge(edgeId);
```

L'ID doit être un UUID sous forme de `string`.

## Ajouter un edge

```typescript
await vault.post_edge(
    edge,
    token
);
```

## Modifier un edge

```typescript
await vault.put_edge(
    edge,
    token
);
```

## Supprimer un edge

```typescript
await vault.delete_edge(
    edgeId,
    token
);
```

Les edges sont automatiquement chiffrés par Rust avant d'être envoyés au backend.

---

# History

La `history` est accessible uniquement en lecture depuis TypeScript :

```typescript
const history = vault.get_history();
```

Les entrées `History` sont générées automatiquement par Rust lors des modifications et suppressions de nodes.

TypeScript ne doit pas créer ou modifier directement les entrées d'historique.

---

# Security Events

Les événements de sécurité sont accessibles uniquement en lecture :

```typescript
const events = vault.get_events();
```

Les événements sont gérés en interne par Rust.

TypeScript ne doit pas créer ou modifier directement les `SecurityEvent`.

---

# Authentification

Les méthodes qui communiquent avec le backend acceptent un token :

```typescript
await vault.post_node(
    node,
    accessToken
);
```

Le token est transmis au backend dans le header :

```http
Authorization: <token>
```

Le token n'est pas stocké dans le `Vault`.

---

# Chiffrement

Le frontend ne chiffre pas directement les données.

Lorsqu'une donnée est envoyée au backend :

```text
TypeScript
    ↓
WasmVault
    ↓
Rust
    ↓
Chiffrement
    ↓
Backend
```

Lorsqu'une donnée est récupérée :

```text
Backend
    ↓
Données chiffrées
    ↓
Rust
    ↓
Déchiffrement
    ↓
WasmVault
    ↓
TypeScript
```

Le backend ne reçoit donc jamais les données sensibles en clair.

Les éléments suivants sont chiffrés avant d'être envoyés au backend :

- `Node`
- `Edge`
- `History`
- `SecurityEvent`

Les métadonnées nécessaires au backend peuvent rester en clair selon les modèles `CypherNode` et `CypherEdge`.

---

# Exemple complet

```typescript
import init, {
    WasmVault,
    set_base_url
} from "./wasm/pkg/wasm";

async function loadVault() {
    // Initialisation du WASM
    await init();

    // Configuration de l'API
    set_base_url("https://api.example.com");

    // Création du Vault
    const vault = await new WasmVault(
        userId,
        masterPassword,
        userSalt,
        accessToken
    );

    // Récupération des données
    const nodes = vault.get_nodes();
    const edges = vault.get_edges();
    const history = vault.get_history();
    const events = vault.get_events();

    console.log(nodes);
    console.log(edges);
    console.log(history);
    console.log(events);

    // Ajout d'un node
    await vault.post_node(
        newNode,
        accessToken
    );

    // Modification d'un node
    await vault.put_node(
        updatedNode,
        accessToken
    );

    // Suppression d'un node
    await vault.delete_node(
        nodeId,
        accessToken
    );
}
```

---

# Architecture

```text
┌─────────────────────────┐
│       Projet Rust       │
│                         │
│      project_core       │
│           ↓             │
│      VaultService       │
│           ↓             │
│       ApiService        │
│           ↓             │
│          WASM           │
│           ↓             │
│         pkg/            │
└────────────┬────────────┘
             │
             │ copier
             ↓
┌─────────────────────────┐
│     Projet React / TS   │
│                         │
│        wasm/pkg/        │
│            ↓            │
│        WasmVault        │
│            ↓            │
│     Application React   │
└─────────────────────────┘
```

Le fonctionnement global est :

```text
                         ┌──────────────────┐
                         │      React       │
                         │   TypeScript     │
                         └────────┬─────────┘
                                  │
                                  │ données
                                  │ en clair
                                  ↓
                         ┌──────────────────┐
                         │    WasmVault     │
                         └────────┬─────────┘
                                  │
                                  ↓
                         ┌──────────────────┐
                         │      Rust        │
                         │                  │
                         │  VaultService    │
                         │  ApiService      │
                         │  Encryption      │
                         │  Decryption      │
                         └────────┬─────────┘
                                  │
                                  │ données
                                  │ chiffrées
                                  ↓
                         ┌──────────────────┐
                         │     Backend      │
                         │                  │
                         │  Données         │
                         │  chiffrées       │
                         └──────────────────┘
```

Le code métier et la logique cryptographique restent dans **Rust**.

TypeScript sert principalement à utiliser le WASM et à manipuler les données déchiffrées.

---

# Recompiler après une modification Rust

Après chaque modification du code Rust :

```bash
wasm-pack build crates/wasm --target web
```

Le nouveau package est généré dans :

```text
crates/wasm/pkg/
```

Il faut ensuite remplacer le dossier `pkg` présent dans le projet React :

```text
Rust
└── crates/
    └── wasm/
        └── pkg/
             ↓
             ↓ copier
             ↓
React
└── wasm/
    └── pkg/
```

> Le projet React n'a pas besoin du projet Rust complet. Seul le package `pkg` généré est nécessaire pour utiliser le WASM.

---

# Résumé

Le principe est de garder toute la logique sensible dans Rust :

```text
React
  ↓
WasmVault
  ↓
Rust
  ├── Déchiffrement
  ├── Manipulation du Vault
  ├── Génération de l'History
  ├── Chiffrement
  └── Communication avec l'API
          ↓
       Backend
```

Le frontend travaille avec les données déchiffrées, tandis que le backend ne reçoit et ne stocke que les données chiffrées nécessaires.

Le projet Rust et le projet React restent totalement indépendants. Le seul élément partagé entre les deux projets est le package `pkg` généré par `wasm-pack`.