---
name: openscan-crypto
description: Navigate and query crypto networks via OpenScan infrastructure. Use when the user asks about blockchain data — balances (ETH, ERC20, BTC), blocks, transactions, gas prices, mempool, fee estimates, token lookups, event decoding, RPC endpoints, or ENS resolution. Supports Ethereum, Bitcoin, Arbitrum, Optimism, Base, Polygon, BNB, Sepolia, and Aztec. Powered by @openscan/network-connectors and @openscan/metadata.
---

# OpenScan Crypto Network Skill

Navigate and query crypto networks using OpenScan's infrastructure. Data comes from `@openscan/metadata` (CDN) and `@openscan/network-connectors` (RPC).

## CLI Location

```
skills/openscan-crypto/scripts/crypto-cli.mjs
```

Run with: `node <skill_dir>/scripts/crypto-cli.mjs <command> [args]`

## Metadata Commands

### List networks
```bash
crypto-cli.mjs networks
```

### List RPC endpoints
```bash
crypto-cli.mjs rpcs <chain>              # All public RPCs
crypto-cli.mjs rpcs <chain> --private    # Only tracking:none RPCs
```

### Look up token
```bash
crypto-cli.mjs token <symbol|address>                # Search all mainnets
crypto-cli.mjs token <symbol|address> --chain <chain> # Specific chain
```

### Event signatures
```bash
crypto-cli.mjs events [--chain <chain>]     # List known events
crypto-cli.mjs decode-event <topic_hash>    # Decode one topic
```

### Labeled addresses & profiles
```bash
crypto-cli.mjs addresses [--chain <chain>]
crypto-cli.mjs profile networks ethereum
crypto-cli.mjs profile apps openscan
```

## EVM Query Commands

All EVM commands accept `--chain <chain>` (default: ethereum) and `--private` (use tracking:none RPCs only).

### Check balance
```bash
crypto-cli.mjs balance <address>                           # Native balance (ETH)
crypto-cli.mjs balance vitalik.eth                          # ENS name supported
crypto-cli.mjs balance <address> --token USDC              # + ERC20 balance
crypto-cli.mjs balance <address> --chain arbitrum           # On Arbitrum
crypto-cli.mjs balance <address> --token USDC --chain base  # USDC on Base
```
Returns native balance in human-readable format (e.g., "32.12 ETH") plus raw wei. Token balance includes symbol, decimals, and formatted amount.

### Multi-chain balance
```bash
crypto-cli.mjs multi-balance <address>                     # All mainnet chains
crypto-cli.mjs multi-balance vitalik.eth                    # ENS supported
crypto-cli.mjs multi-balance <address> --private           # Privacy RPCs only
```
Queries the same address across ALL mainnet EVM chains in parallel. Shows balances sorted by chains with funds first.

### Get block info
```bash
crypto-cli.mjs block                    # Latest block
crypto-cli.mjs block latest             # Same
crypto-cli.mjs block 19000000           # By number
crypto-cli.mjs block 0xabcdef...        # By hash (66 chars)
```
Returns: number, hash, timestamp, gasUsed, gasLimit, baseFee, txCount, miner.

### Transaction details
```bash
crypto-cli.mjs tx <0xhash>
crypto-cli.mjs tx <0xhash> --chain arbitrum
```
Returns: hash, blockNumber, from, to, value (in ETH), gasPrice, nonce, input data.

### Transaction receipt
```bash
crypto-cli.mjs receipt <0xhash>
```
Returns: status (success/reverted), gasUsed, effectiveGasPrice, contract address (if deploy), logs with decoded event names from metadata.

### Gas prices
```bash
crypto-cli.mjs gas                      # Ethereum gas
crypto-cli.mjs gas --chain base         # Base gas
crypto-cli.mjs gas --chain arbitrum     # Arbitrum gas
```
Returns: gasPrice, maxPriorityFeePerGas, baseFee — all in gwei.

### Read contract (eth_call)
```bash
crypto-cli.mjs call <to_address> <calldata_hex> [--block <tag>]
```
For raw contract reads. Use for custom ABI calls.

### Event logs
```bash
crypto-cli.mjs logs --address <contract> --topic <topic_hash> [--from <block>] [--to <block>]
```
Returns up to 50 logs. Default range: latest block only.

### Check if address is contract
```bash
crypto-cli.mjs code <address>
```
Returns: isContract (bool), codeSize, truncated bytecode.

### Transaction count (nonce)
```bash
crypto-cli.mjs nonce <address>
```

## Bitcoin Commands

Bitcoin queries use the mempool.space REST API (no JSON-RPC needed).

### Blockchain overview
```bash
crypto-cli.mjs btc-info
```
Returns: block height, best hash, difficulty, mempool stats, recommended fees — all in one call.

### Block details
```bash
crypto-cli.mjs btc-block                # Latest block
crypto-cli.mjs btc-block 800000         # By height
crypto-cli.mjs btc-block 0000000...     # By hash (64 chars)
```

### Transaction details
```bash
crypto-cli.mjs btc-tx <txid>
```
Returns: confirmation status, fee (sats + BTC), fee rate (sat/vB), inputs/outputs with addresses and values.

### Mempool state
```bash
crypto-cli.mjs btc-mempool
```
Returns: tx count, vsize, total fees, recommended fee rates, 5 most recent txs.

### Fee estimates
```bash
crypto-cli.mjs btc-fee
```
Returns: fastest, halfHour, hour, economy, minimum — all in sat/vB.

### Address balance
```bash
crypto-cli.mjs btc-address <address>
```
Returns: balance (BTC + sats), total received/sent, tx count, UTXO count.

## Chain Aliases

| Alias | Chain ID | Network |
|-------|----------|---------|
| ethereum, eth, mainnet | 1 | Ethereum |
| optimism, op | 10 | Optimism |
| bnb, bsc | 56 | BNB Smart Chain |
| polygon, matic, pol | 137 | Polygon |
| base | 8453 | Base |
| arbitrum, arb | 42161 | Arbitrum One |
| aztec | 677868 | Aztec |
| sepolia | 11155111 | Sepolia Testnet |
| bitcoin, btc | bip122:... | Bitcoin Mainnet |

Numeric chain IDs also work (e.g., `1`, `42161`).

## Output

All commands output JSON to stdout. The agent can parse and format as needed.

Numeric values are pre-formatted:
- Balances: human-readable (e.g., "32.12 ETH") + raw wei
- Gas: in gwei
- Timestamps: ISO 8601
- Hex numbers: converted to decimal strings

### Explorer Links

EVM commands that return on-chain entities include an `explorerLink` field with a direct URL to [openscan.eth.link](https://openscan.eth.link):

| Command | explorerLink points to |
|---------|------------------------|
| `balance` | address page |
| `multi-balance` | address page per chain |
| `block` | block page |
| `tx` | transaction page |
| `receipt` | transaction page |
| `code` | address page |
| `nonce` | address page |
| `token` | token contract address page |
| `logs` | transaction page per log |
| `btc-block` | Bitcoin block page |
| `btc-tx` | Bitcoin transaction page |
| `btc-address` | Bitcoin address page |

URL patterns:
- EVM: `https://openscan.eth.link/#/{chainId}/{type}/{id}`
- Bitcoin mainnet: `https://openscan.eth.link/#/btc/{type}/{id}`
- Bitcoin testnet4: `https://openscan.eth.link/#/tbtc/{type}/{id}`

Always show this link to the user so they can explore the data further in the UI.

## Caching

Metadata cached in `~/.cache/openscan-crypto/` (6h TTL). RPC responses are NOT cached.

## ENS Support

All EVM address commands accept `.eth` names (e.g., `vitalik.eth`). ENS is resolved on Ethereum mainnet automatically. Works with: `balance`, `multi-balance`, `code`, `nonce`.

## Security

- **READ-ONLY** — no transaction signing, no private key handling
- **Public RPCs** — no API keys needed
- `--private` flag restricts to tracking:none RPCs
- Dangerous methods (sendTransaction, etc.) are NOT exposed

## Natural Language Mapping

| User says | Command |
|-----------|---------|
| "What's Vitalik's ETH balance?" | `balance 0xd8dA...96045` |
| "How much USDC does 0x... have on Base?" | `balance 0x... --token USDC --chain base` |
| "Show the latest Ethereum block" | `block latest` |
| "What's gas like on Arbitrum?" | `gas --chain arbitrum` |
| "Look up this transaction" | `tx 0x...` |
| "Did this tx succeed?" | `receipt 0x...` |
| "Is 0x... a contract?" | `code 0x...` |
| "What networks does OpenScan support?" | `networks` |
| "What's the USDC contract address?" | `token USDC` |
| "Show privacy-friendly Polygon RPCs" | `rpcs polygon --private` |
| "Show vitalik.eth balance on all chains" | `multi-balance vitalik.eth` |
| "What's the latest Bitcoin block?" | `btc-info` or `btc-block` |
| "How full is the Bitcoin mempool?" | `btc-mempool` |
| "What are Bitcoin fees right now?" | `btc-fee` |
| "Look up this Bitcoin transaction" | `btc-tx <txid>` |
| "Check Satoshi's balance" | `btc-address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` |
| "Show Bitcoin block 800000" | `btc-block 800000` |
