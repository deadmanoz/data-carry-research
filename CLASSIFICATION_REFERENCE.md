# Stage 3 Protocol Classification Reference

**Complete technical reference for P2MS protocol classification sequence, detection methods, and variants.**

This document provides comprehensive information about how Stage 3 classifies P2MS outputs across all supported protocols.

---

## Table of Contents

- [Classification Order](#classification-order)
- [Protocol Classifiers](#protocol-classifiers)
  - [1. Omni Layer](#1-omni-layer)
  - [2. Chancecoin](#2-chancecoin)
  - [3. Bitcoin Stamps](#3-bitcoin-stamps)
  - [4. Counterparty](#4-counterparty)
  - [5. ASCII Identifier Protocols](#5-ascii-identifier-protocols)
  - [6. PPk](#6-ppk)
  - [7. WikiLeaks Cablegate](#7-wikileaks-cablegate)
  - [8. OP_RETURN Signalled](#8-op_return-signalled)
  - [9. DataStorage](#9-datastorage)
  - [10. LikelyDataStorage](#10-likelydatastorage)
  - [11. LikelyLegitimateMultisig](#11-likelylegitimatemultisig)
  - [12. Unknown (Fallback)](#12-unknown-fallback)
- [Critical Implementation Details](#critical-implementation-details)

---

## Classification Order

**Source**: [src/processor/stage3/mod.rs](src/processor/stage3/mod.rs)

Classifications are tried in protocol precedence order, with the first match winning:

1. **Omni Layer** - Exclusive transport via Exodus address
2. **Chancecoin** - Marked by `CHANCECO` identifier
3. **Bitcoin Stamps** - MUST precede Counterparty (can be embedded IN Counterparty)
4. **Counterparty** - Checked after Stamps to avoid misclassification
5. **ASCII Identifier Protocols** - `TB0001`, `TEST01`, Metronotes (`METROXMN`), others
6. **PPk** - "Blockchain infrastructure protocol" with marker pubkey
7. **WikiLeaks Cablegate** - Specific historical artifact (produces Data Storage classifications)
8. **OP_RETURN Signalled** - OP_RETURN-based protocols (Protocol47930, `CLIPPERZ`, Generic ASCII)
9. **Data Storage** - Generic data embedding patterns in P2MS outputs
10. **Likely Data Storage** - Valid EC points but suspicious patterns, OR invalid EC points
11. **Likely Legitimate Multisig** - All valid EC points
12. **Unknown** - Fallback

---

## Protocol Classifiers

### 1. Omni Layer

**File**: [src/processor/stage3/omni.rs](src/processor/stage3/omni.rs)

#### Detection Checks
- **Primary**: Adjacent output to Exodus address `1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P`
- **Data Extraction**: P2MS data from second/third pubkey slots (positions 1 and 2)
- **Deobfuscation**: SHA256-based sequence detection with sender address
- **Message Parsing**: 4-byte header (version + message type)

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

Omni Layer uses 7 semantic variants + 1 special case to categorise operations:

- `OmniTransfer` - Types 0,2,4,5: Peer-to-peer asset transfers (USDT, etc.)
- `OmniDistribution` - Type 3: Broadcast distributions to all token holders (dividends/airdrops)
- `OmniIssuance` - Types 50,51,52,54,55: Property creation, crowdsales, token minting
- `OmniDestruction` - Type 56: Token burning/revocation
- `OmniDEX` - Types 20,22,25-28: Decentralised exchange operations
- `OmniAdministration` - Types 53,70,71,72,185,186: Administrative controls, restrictions, freezing
- `OmniUtility` - Types 31,200: Notifications and arbitrary data storage
- `OmniFailedDeobfuscation` - Exodus address present but deobfuscation failed

---

### 2. Chancecoin

**File**: [src/processor/stage3/chancecoin.rs](src/processor/stage3/chancecoin.rs)

#### Detection Checks
- **Signature**: 8-byte "CHANCECO" (`0x4348414e4345434f`) in concatenated P2MS data
- **Data Location**: Second pubkey slot (index 1) of 1-of-2, 1-of-2 used exclusively
- **Format**: Each output: `[length:1][data:0-32][padding:0-32]` = 33 bytes
- **No obfuscation**: Data stored directly

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `ChancecoinSend` - Token transfer (ID=0)
- `ChancecoinOrder` - DEX order (ID=10)
- `ChancecoinBTCPay` - BTC payment (ID=11)
- `ChancecoinRoll` - Bet resolution (ID=14)
- `ChancecoinBet` - Gambling bet (ID=40/41)
- `ChancecoinCancel` - Cancel order (ID=70)
- `ChancecoinUnknown` - Unknown message type

---

### 3. Bitcoin Stamps

**File**: [src/processor/stage3/stamps.rs](src/processor/stage3/stamps.rs)

**Priority**: MUST be checked BEFORE Counterparty (can be embedded IN Counterparty)

#### Detection Checks
- **Burn Keys**: Stamps-specific burn patterns
  - `Stamps22Pattern`, `Stamps33Pattern`, `Stamps0202Pattern`, `Stamps0303Pattern`
- **Multisig Patterns**: exclusively uses 1-of-3
- **ARC4 Decryption**: First input txid as key
- **Signature Validation**: `STAMP:` or `stamp:` in decrypted payload
- **Multi-output**: Concatenate ALL P2MS chunks BEFORE decryption
- **Transport Detection**: Checks for existence of `CNTRPRTY` prefix to determine transport

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

Content detection follows encoding-over-content priority (compression → images → JSON → HTML → text → binary):

- `StampsCompressed` - Compressed data (ZLIB, GZIP) - detected before decompression
- `StampsClassic` - Image data (PNG, GIF, JPG, SVG, WebP, BMP)
- `StampsSRC20` - SRC-20 fungible token JSON
- `StampsSRC721` - SRC-721 NFT JSON
- `StampsSRC101` - SRC-101 domain name JSON
- `StampsHTML` - HTML documents (with `<html>`, `<!DOCTYPE>`, or `<style>` tags)
- `StampsData` - Generic data (XML, plain text, binary, non-SRC JSON)
- `StampsUnknown` - Valid burn pattern OR burn-pattern-only detection

---

### 4. Counterparty

**File**: [src/processor/stage3/counterparty.rs](src/processor/stage3/counterparty.rs)

**Priority**: Checked AFTER Stamps to avoid misclassifying Stamps-over-Counterparty

#### Detection Checks
- **Burn Key Filter**: Skips transactions with Stamps burn keys
- **ARC4 Decryption**: First input txid as key
- **Signature**: `CNTRPRTY` (8 bytes) at offset 0 or 1 of decrypted data
- **Multisig Patterns**:
  - **Tier 1**: 1-of-3, 1-of-2
  - **Tier 2**: 2-of-2, 2-of-3, 3-of-3
- **Data Extraction**: Bytes [1..32] from compressed pubkeys (31 bytes each)

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

The codebase maps 21 Counterparty message types to 7 semantically coherent variant categories:

- **`CounterpartyTransfer`** - Asset transfers between parties
  - Message types: Send (0), EnhancedSend (2), Mpma (3), Sweep (4), Dividend (50)

- **`CounterpartyIssuance`** - Asset creation and minting
  - Message types: Issuance (20/21/22), FairMinter (90), FairMint (91)

- **`CounterpartyDestruction`** - Asset destruction and burns
  - Message types: Destroy (110), Burn (60)

- **`CounterpartyDEX`** - Decentralised exchange operations
  - Message types: Order (10), BtcPay (11), Dispenser (12), Cancel (70)

- **`CounterpartyOracle`** - Oracle data publication
  - Message types: Broadcast (30)

- **`CounterpartyGaming`** - Betting and gaming operations
  - Message types: Bet (40), Rps (80), RpsResolve (81)

- **`CounterpartyUtility`** - UTXO technical operations
  - Message types: Utxo (100), Attach (101), Detach (102)

**Semantic Coherence**: Each variant groups message types with a single, clear purpose. For example, FairMint creates new tokens (issuance), while Dividend redistributes existing assets (transfer).

**Note**: The full 21-value `CounterpartyMessageType` enum is preserved in the database `additional_metadata_json` column for detailed analysis.

---

### 5. ASCII Identifier Protocols

**File**: [src/processor/stage3/ascii_identifier_protocols.rs](src/processor/stage3/ascii_identifier_protocols.rs)

#### Detection Checks
- **`TB0001`**: Signature in bytes 1-7 of FIRST or SECOND pubkey
- **`TEST01`**: Signature in bytes 1-7 of FIRST pubkey ONLY
- **`METROXMN`**: `METROXMN` anywhere in second pubkey
- **Other**: Allowlist of known signatures (`NEWBCOIN`, `PRVCY`) in first 20 bytes

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `AsciiIdentifierTB0001` - `TB0001` protocol (~185 txs, May 2015)
- `AsciiIdentifierTEST01` - `TEST01` protocol (~91 txs, May 2015)
- `AsciiIdentifierMetronotes` - Metronotes/`METROXMN` (~100 txs, March 2015)
- `AsciiIdentifierOther` - Other ASCII protocols (`NEWBCOIN`, `PRVCY`)
- `AsciiIdentifierUnknown` - Unknown ASCII identifier

**CRITICAL**: `TEST01` uses FIRST pubkey; `TB0001` uses FIRST or SECOND.

---

### 6. PPk

**File**: [src/processor/stage3/ppk.rs](src/processor/stage3/ppk.rs)

#### Detection Checks
- **Primary**: Marker pubkey `0320a0de360cc2ae8672db7d557086a4e7c8eca062c0a5a4ba9922dee0aacf3e12` in position 2 of P2MS
- **Parser**: Supports both compressed (33-byte, 0x21) and uncompressed (65-byte, 0x41) pubkeys
- **Variant Detection**: Checks `OP_RETURN` data for `RT` TLV, quoted numbers, or text messages. RT (Resource Tag) uses TLV structure: 2-byte `RT` + 1-byte length + JSON payload
- **Full Data Extraction**: Uses complete P2MS + `OP_RETURN` payload

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `PPkProfile` - JSON profile data via RT (Resource Tag) transport. RT data may be encoded in OP_RETURN (1-of-2 multisig) or split between P2MS pubkey #3 and OP_RETURN (1-of-3 multisig). Total: ~2,010 transactions. (content-type: application/json)
- `PPkRegistration` - Quoted number strings like "313", "421" (content-type: text/plain)
- `PPkMessage` - Promotional messages containing "PPk"/"ppk" OR ≥80% printable ASCII (content-type: text/plain)
- `PPkUnknown` - Marker present but no specific variant detected (content-type: application/octet-stream)

---

### 7. WikiLeaks Cablegate

**File**: [src/processor/stage3/wikileaks_cablegate.rs](src/processor/stage3/wikileaks_cablegate.rs)

**Priority**: Specific historical artifact, checked before generic DataStorage

#### Detection Checks
- **Primary**: WikiLeaks donation address `1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v`

#### Variant
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `DataStorageWikiLeaksCablegate` - WikiLeaks Cablegate archive (under DataStorage protocol)

---

### 8. OP_RETURN Signalled

**File**: [src/processor/stage3/opreturn_signalled.rs](src/processor/stage3/opreturn_signalled.rs)

**Priority**: After PPk, as some PPk variants have ASCII data in `OP_RETURN` which would trigger this classifier

#### Detection Checks
Detection order within this classifier:

1. **Protocol47930**: `0xbb3a` marker + 2-of-2 multisig
   - Binary marker: `0xbb3a` (47930 in decimal)
2. **`CLIPPERZ`**: `CLIPPERZ REG` or `CLIPPERZ 1.0 REG` + 2-of-2 multisig
3. **GenericASCII**: `OP_RETURN` with ASCII content
   - (≥80% printable ASCII AND ≤40 bytes) OR ≥5 consecutive ASCII chars
   - Examples: `PRVCY`, `unsuccessful`, `@DEVCHA`

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `OpReturnProtocol47930` - Binary marker `0xbb3a` + 2-of-2 multisig
- `OpReturnCLIPPERZ` - `CLIPPERZ` notarisation + 2-of-2 multisig
- `OpReturnGenericASCII` - Generic ASCII `OP_RETURN` protocols (catch-all)

---

### 9. Data Storage

**File**: [src/processor/stage3/datastorage.rs](src/processor/stage3/datastorage.rs)

**Priority**: Generic data embedding patterns

#### Detection Checks

##### Binary Signatures
- **PDF**: `%PDF` (0x25504446)
- **PNG**: `‰PNG` (0x89504e47)
- **JPEG**: `0xFFD8FF`
- **GIF**: `GIF8`
- **ZIP/JAR/DOCX**: `PK` (0x504b)
- **RAR**: `Rar!`
- **7-Zip**: `7z` (0x377abcaf)
- **GZIP**: `0x1f8b08`
- **BZIP2**: `BZh[1-9]`
- **ZLIB**: `0x78` + valid CMF-FLG checksum at offsets 0, 5-6, or 7-8
- **TAR**: `ustar` magic at offset 257

##### Other Patterns
- **Proof of Burn**: All 0xFF bytes (32, 33, or 65 byte patterns)
- **File Metadata**: URLs, file extensions, keywords
- **Text Data**: ≥50% printable ASCII, ≥4 chars
- **Null Data**: All zero/null bytes

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `DataStorageProofOfBurn` - All 0xFF burn patterns
- `DataStorageFileMetadata` - File sharing metadata
- `DataStorageEmbeddedData` - Data embedded in pubkey coordinates
- `DataStorageWikiLeaksCablegate` - WikiLeaks Cablegate archive
- `DataStorageNullData` - Null/zero byte padding
- `DataStorageGeneric` - Other data storage patterns

---

### 10. Likely Data Storage

**File**: [src/processor/stage3/likely_data_storage.rs](src/processor/stage3/likely_data_storage.rs)

#### Detection Checks

Detection order within this classifier:

**Check 1**: Invalid EC Points
- **Method**: Full secp256k1 EC point validation via `validate_from_metadata()`
- **Trigger**: ANY pubkey fails validation (≥1 invalid EC point)
- **Rationale**: Even a single invalid EC point strongly suggests data storage, as legitimate multisig wallets would never generate keys that aren't on the curve
- **Catches**:
  - Invalid prefixes (0xb6, 0x01, 0xe1 instead of 0x02/0x03/0x04)
  - Valid prefixes but coordinates not on secp256k1 curve
  - Malformed keys of wrong length

**Check 2**: High Output Count
- **Criteria**: ≥5 P2MS outputs with ALL valid EC points
- **Validation**: All pubkeys must pass full EC point validation

**Check 3**: Dust Amounts
- **Criteria**: ALL P2MS outputs ≤1000 sats with valid EC points
- **Threshold**: 1000 satoshis per output

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `InvalidECPoint` - Invalid EC points (not on secp256k1 curve - indicative of data embedding)
- `HighOutputCount` - 5+ P2MS outputs with valid EC points
- `DustAmount` - P2MS outputs with dust-level amounts (≤1000 sats)

---

### 11. Likely Legitimate Multisig

**File**: [src/processor/stage3/likely_legitimate.rs](src/processor/stage3/likely_legitimate.rs)

#### Detection Checks
- **Primary**: ALL pubkeys are valid EC points on secp256k1 curve
- **Accepts**: Duplicate keys (likely wallet/user error)
- **Accepts**: Null-padded keys (all-zero pubkeys) if real_key_count > 0

#### Variants
**Source**: [src/types/stage3.rs](src/types/stage3.rs)

- `LegitimateMultisig` - Standard multisig with valid EC points
- `LegitimateMultisigDupeKeys` - Valid EC points but duplicate keys
- `LegitimateMultisigWithNullKey` - Mix of valid EC points + all-null pubkeys

**Spendability**: M ≤ real_keys (null keys don't count toward signature threshold)

---

### 12. Unknown (Fallback)

**File**: [src/processor/stage3/mod.rs](src/processor/stage3/mod.rs)
**Priority**: Always matches (last resort)

#### Characteristics
- No protocol signature found
- Applied when all other classifiers return `None`
- Still produces output classifications with spendability analysis
- Hopefully no P2MS transactions/outputs reach this stage!

---

## Critical Implementation Details

### Classification Philosophy

**Varied forms of detection**:
- Key Burn identifiers (e.g., Bitcoin Stamps)
- Protocol marker after deobfuscation (e.g., Counterparty `CNTRPRTY`)
- Protocol markers in the clear in P2MS (e.g., Chancecoin `CHANCECO`, `TB0001` etc)
- Protocol markers in `OP_RETURN` (e.g., `0xbb3a`, `CLIPPERZ`)
- Adjacent address markers (e.g., Exodus address for Omni, WikiLeaks donation address for WikiLeaks Cablegate)
- Pubkey marker patterns (e.g., PPk marker pubkey)
- Data pattern signatures (e.g., file magic numbers for DataStorage)
- EC point validation

**No Height Filtering**: Historical block ranges documented for reference only - detection based on signatures, not assumed block ranges.

### DB FK Ordering

**Source**: [src/processor/stage3/mod.rs](src/processor/stage3/mod.rs)

1. Insert transaction classification (FK parent)
2. Insert output classifications (FK child)

This ensures `p2ms_output_classifications.txid → transaction_classifications.txid` FK constraint is satisfied.
