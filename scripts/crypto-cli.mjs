#!/usr/bin/env node

/**
 * openscan-crypto CLI
 * 
 * Phase 1: Metadata commands (networks, rpcs, token, events, decode-event, addresses, profile)
 * Phase 2: EVM queries (balance, block, tx, receipt, gas, call, logs, code, nonce)
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { ClientFactory } from "@openscan/network-connectors";

// ── Config ──────────────────────────────────────────────────────────────────

const CDN_BASE = "https://cdn.jsdelivr.net/npm/@openscan/metadata@1.1.1-alpha.0/dist";
const CACHE_DIR = join(homedir(), ".cache", "openscan-crypto");
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

// Chain name aliases → chainId (or btc slug)
const CHAIN_ALIASES = {
  ethereum: 1, eth: 1, mainnet: 1,
  optimism: 10, op: 10,
  bnb: 56, bsc: 56,
  "bnb-testnet": 97,
  polygon: 137, matic: 137, pol: 137,
  base: 8453,
  arbitrum: 42161, arb: 42161,
  sepolia: 11155111,
  hardhat: 31337,
  bitcoin: "btc/mainnet", btc: "btc/mainnet",
  "btc-testnet4": "btc/testnet4",
};

// Reverse map: chainId → display name (populated from networks.json)
let networkNames = {};

// ── Cache layer ─────────────────────────────────────────────────────────────

async function ensureCacheDir() {
  if (!existsSync(CACHE_DIR)) {
    await mkdir(CACHE_DIR, { recursive: true });
  }
}

function cachePathFor(key) {
  return join(CACHE_DIR, key.replace(/\//g, "_") + ".json");
}

async function getCached(key) {
  const path = cachePathFor(key);
  if (!existsSync(path)) return null;
  try {
    const raw = await readFile(path, "utf-8");
    const { ts, data } = JSON.parse(raw);
    if (Date.now() - ts > CACHE_TTL_MS) return null;
    return data;
  } catch {
    return null;
  }
}

async function setCache(key, data) {
  await ensureCacheDir();
  await writeFile(cachePathFor(key), JSON.stringify({ ts: Date.now(), data }));
}

// ── CDN fetch ───────────────────────────────────────────────────────────────

async function fetchMetadata(path) {
  const cacheKey = path;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const url = `${CDN_BASE}/${path}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);

  const contentType = res.headers.get("content-type") || "";
  let data;
  if (contentType.includes("json") || path.endsWith(".json")) {
    data = await res.json();
  } else {
    data = await res.text();
  }
  await setCache(cacheKey, data);
  return data;
}

// ── Chain resolution ────────────────────────────────────────────────────────

function resolveChain(input) {
  if (!input) return null;
  const lower = input.toLowerCase().trim();
  
  // Direct alias
  if (CHAIN_ALIASES[lower] !== undefined) return CHAIN_ALIASES[lower];
  
  // Numeric chain ID
  const num = parseInt(lower, 10);
  if (!isNaN(num)) return num;

  return null;
}

function chainToRpcPath(chainId) {
  if (typeof chainId === "string" && chainId.startsWith("btc/")) {
    return `rpcs/${chainId}.json`;
  }
  return `rpcs/evm/${chainId}.json`;
}

function chainToTokenPath(chainId) {
  return `tokens/evm/${chainId}/all.json`;
}

function chainToEventsPath(chainId) {
  return `events/evm/${chainId}`;
}

// ── Output helpers ──────────────────────────────────────────────────────────

const EXPLORER_BASE = "https://openscan.eth.link";

const BTC_EXPLORER_SLUG = {
  "btc/mainnet": "btc",
  "btc/testnet4": "tbtc",
};

function explorerUrl(chainId, type, id) {
  if (typeof chainId === "number") {
    return `${EXPLORER_BASE}/#/${chainId}/${type}/${id}`;
  }
  const btcSlug = BTC_EXPLORER_SLUG[chainId];
  if (btcSlug) {
    return `${EXPLORER_BASE}/#/${btcSlug}/${type}/${id}`;
  }
  return undefined;
}

function out(data) {
  console.log(JSON.stringify(data, null, 2));
}

function err(msg) {
  console.error(`Error: ${msg}`);
  process.exit(1);
}

// ── Commands ────────────────────────────────────────────────────────────────

async function cmdNetworks() {
  const data = await fetchMetadata("networks.json");
  const result = data.networks.map(n => ({
    name: n.name,
    shortName: n.shortName,
    type: n.type,
    chainId: n.chainId || n.networkId,
    currency: n.currency,
    isTestnet: n.isTestnet || false,
  }));
  out({ count: result.length, networks: result });
}

async function cmdRpcs(chainInput, privateOnly) {
  const chainId = resolveChain(chainInput);
  if (chainId === null) err(`Unknown chain: ${chainInput}. Use 'networks' to list available chains.`);

  const path = chainToRpcPath(chainId);
  const data = await fetchMetadata(path);

  let endpoints = data.endpoints.filter(e => e.isPublic);
  if (privateOnly) {
    endpoints = endpoints.filter(e => e.tracking === "none");
  }

  out({
    networkId: data.networkId,
    totalEndpoints: endpoints.length,
    endpoints: endpoints.map(e => ({
      url: e.url,
      provider: e.provider,
      tracking: e.tracking,
      isOpenSource: e.isOpenSource,
    })),
  });
}

async function cmdToken(query, chainFilter) {
  const queryLower = query.toLowerCase();
  const isAddress = queryLower.startsWith("0x") && queryLower.length === 42;

  // Determine which chains to search
  const networksData = await fetchMetadata("networks.json");
  let chainsToSearch = networksData.networks
    .filter(n => n.type === "evm" && !n.isTestnet)
    .map(n => n.chainId);

  if (chainFilter) {
    const resolved = resolveChain(chainFilter);
    if (resolved === null || typeof resolved === "string") {
      err(`Token search only works for EVM chains. Unknown chain: ${chainFilter}`);
    }
    chainsToSearch = [resolved];
  }

  const results = [];
  for (const chainId of chainsToSearch) {
    try {
      const data = await fetchMetadata(chainToTokenPath(chainId));
      const network = networksData.networks.find(n => n.chainId === chainId);
      const networkName = network?.shortName || `Chain ${chainId}`;

      for (const token of data.tokens) {
        const match = isAddress
          ? token.address.toLowerCase() === queryLower
          : token.symbol.toLowerCase() === queryLower || token.name.toLowerCase().includes(queryLower);
        
        if (match) {
          results.push({
            ...token,
            chain: networkName,
            chainId,
            explorerLink: explorerUrl(chainId, "address", token.address),
          });
        }
      }
    } catch {
      // Chain may not have token data
    }
  }

  if (results.length === 0) {
    out({ found: false, query, message: `No token found matching "${query}"` });
  } else {
    out({ found: true, count: results.length, tokens: results });
  }
}

async function cmdEvents(chainFilter) {
  const chainId = chainFilter ? resolveChain(chainFilter) : 1; // default Ethereum
  if (chainId === null || typeof chainId === "string") {
    err(`Events only available for EVM chains.`);
  }

  const commonPath = `${chainToEventsPath(chainId)}/common.json`;
  try {
    const data = await fetchMetadata(commonPath);
    const events = Object.entries(data).map(([topic, info]) => ({
      topic,
      event: info.event,
      description: info.description,
    }));
    out({ chainId, count: events.length, events });
  } catch (e) {
    err(`No events data for chain ${chainId}: ${e.message}`);
  }
}

async function cmdDecodeEvent(topic) {
  const topicLower = topic.toLowerCase();

  // Search common events on Ethereum first (most comprehensive)
  const data = await fetchMetadata("events/evm/1/common.json");
  
  if (data[topicLower] || data[topic]) {
    const info = data[topicLower] || data[topic];
    out({ found: true, topic, event: info.event, description: info.description });
    return;
  }

  // Search all chains
  const networksData = await fetchMetadata("networks.json");
  for (const network of networksData.networks) {
    if (network.type !== "evm") continue;
    const chainId = network.chainId;
    try {
      const commonData = await fetchMetadata(`events/evm/${chainId}/common.json`);
      if (commonData[topicLower] || commonData[topic]) {
        const info = commonData[topicLower] || commonData[topic];
        out({ found: true, topic, chain: network.shortName, event: info.event, description: info.description });
        return;
      }
    } catch { /* skip */ }
  }

  out({ found: false, topic, message: "Event topic not found in metadata. It may be a contract-specific event." });
}

async function cmdAddresses(chainFilter) {
  const chainId = chainFilter ? resolveChain(chainFilter) : 1;
  if (chainId === null || typeof chainId === "string") {
    err(`Addresses only available for EVM chains.`);
  }

  try {
    const data = await fetchMetadata(`addresses/evm/${chainId}/all.json`);
    out({
      chainId: data.chainId,
      count: data.count,
      addresses: data.addresses,
    });
  } catch (e) {
    err(`No address data for chain ${chainId}: ${e.message}`);
  }
}

async function cmdProfile(type, id) {
  const validTypes = ["networks", "tokens", "apps", "organizations"];
  if (!validTypes.includes(type)) {
    err(`Invalid profile type: ${type}. Valid: ${validTypes.join(", ")}`);
  }

  let path;
  if (type === "networks") {
    const chainId = resolveChain(id);
    path = `profiles/networks/${chainId || id}.md`;
  } else if (type === "tokens") {
    // Expect format: chainId/address
    path = `profiles/tokens/${id}.md`;
  } else {
    path = `profiles/${type}/${id}.md`;
  }

  try {
    const content = await fetchMetadata(path);
    // For profiles, output as plain text
    console.log(content);
  } catch (e) {
    err(`Profile not found: ${type}/${id}`);
  }
}

// ── EVM client factory ──────────────────────────────────────────────────────

async function getEvmClient(chainInput, privateOnly = false) {
  const chainId = resolveChain(chainInput);
  if (chainId === null) err(`Unknown chain: ${chainInput}`);
  if (typeof chainId === "string") err(`"${chainInput}" is not an EVM chain. Use EVM commands for EVM chains only.`);

  const rpcData = await fetchMetadata(chainToRpcPath(chainId));
  let endpoints = rpcData.endpoints.filter(e => e.isPublic);
  if (privateOnly) endpoints = endpoints.filter(e => e.tracking === "none");

  // Sort: tracking=none first, then limited, then rest
  const order = { none: 0, limited: 1, unspecified: 2, yes: 3 };
  endpoints.sort((a, b) => (order[a.tracking] ?? 9) - (order[b.tracking] ?? 9));

  const rpcUrls = endpoints.map(e => e.url);
  if (rpcUrls.length === 0) err(`No public RPCs available for chain ${chainId}`);

  // Use at most 5 RPCs for fallback
  const client = ClientFactory.createClient(chainId, {
    type: "fallback",
    rpcUrls: rpcUrls.slice(0, 5),
  });
  return { client, chainId };
}

// ── Hex/Wei formatting helpers ──────────────────────────────────────────────

function hexToDecimal(hex) {
  if (!hex || hex === "0x") return "0";
  return BigInt(hex).toString();
}

function weiToEth(weiHex) {
  const wei = BigInt(weiHex);
  const eth = Number(wei) / 1e18;
  return eth;
}

function gweiFromWei(weiHex) {
  const wei = BigInt(weiHex);
  return Number(wei) / 1e9;
}

function formatTokenBalance(balanceHex, decimals) {
  const raw = BigInt(balanceHex);
  const divisor = 10n ** BigInt(decimals);
  const intPart = raw / divisor;
  const fracPart = raw % divisor;
  const fracStr = fracPart.toString().padStart(decimals, "0").replace(/0+$/, "");
  return fracStr ? `${intPart}.${fracStr}` : intPart.toString();
}

function formatBlock(block) {
  if (!block) return null;
  return {
    number: hexToDecimal(block.number),
    hash: block.hash,
    timestamp: new Date(parseInt(block.timestamp, 16) * 1000).toISOString(),
    gasUsed: hexToDecimal(block.gasUsed),
    gasLimit: hexToDecimal(block.gasLimit),
    baseFeePerGas: block.baseFeePerGas ? `${gweiFromWei(block.baseFeePerGas).toFixed(4)} gwei` : null,
    transactionCount: block.transactions ? block.transactions.length : 0,
    miner: block.miner,
    parentHash: block.parentHash,
  };
}

function formatTx(tx) {
  if (!tx) return null;
  return {
    hash: tx.hash,
    blockNumber: tx.blockNumber ? hexToDecimal(tx.blockNumber) : "pending",
    from: tx.from,
    to: tx.to,
    value: `${weiToEth(tx.value)} ETH`,
    valueWei: hexToDecimal(tx.value),
    gasPrice: tx.gasPrice ? `${gweiFromWei(tx.gasPrice).toFixed(4)} gwei` : null,
    maxFeePerGas: tx.maxFeePerGas ? `${gweiFromWei(tx.maxFeePerGas).toFixed(4)} gwei` : null,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas ? `${gweiFromWei(tx.maxPriorityFeePerGas).toFixed(4)} gwei` : null,
    gas: hexToDecimal(tx.gas),
    nonce: hexToDecimal(tx.nonce),
    input: tx.input === "0x" ? "(empty)" : tx.input.length > 74 ? `${tx.input.slice(0, 74)}... (${(tx.input.length - 2) / 2} bytes)` : tx.input,
    type: tx.type ? hexToDecimal(tx.type) : "0",
  };
}

function formatReceipt(receipt) {
  if (!receipt) return null;
  return {
    transactionHash: receipt.transactionHash,
    blockNumber: hexToDecimal(receipt.blockNumber),
    from: receipt.from,
    to: receipt.to,
    status: receipt.status === "0x1" ? "success" : "reverted",
    gasUsed: hexToDecimal(receipt.gasUsed),
    effectiveGasPrice: receipt.effectiveGasPrice ? `${gweiFromWei(receipt.effectiveGasPrice).toFixed(4)} gwei` : null,
    contractAddress: receipt.contractAddress,
    logsCount: receipt.logs ? receipt.logs.length : 0,
    logs: receipt.logs ? receipt.logs.slice(0, 10).map(log => ({
      address: log.address,
      topics: log.topics,
      data: log.data === "0x" ? "(empty)" : log.data.length > 74 ? `${log.data.slice(0, 74)}...` : log.data,
    })) : [],
  };
}

// ── EVM Commands ────────────────────────────────────────────────────────────

async function cmdBalance(address, chainInput, tokenQuery, privateOnly) {
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  // Native balance
  const result = await client.getBalance(address);
  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);

  const nativeBalance = weiToEth(result.data);
  const nativeBalanceWei = hexToDecimal(result.data);

  // Get currency name from metadata
  const networksData = await fetchMetadata("networks.json");
  const network = networksData.networks.find(n => n.chainId === chainId);
  const currency = network?.currency || "ETH";

  const output = {
    address,
    chain: network?.shortName || `Chain ${chainId}`,
    chainId,
    nativeBalance: `${nativeBalance} ${currency}`,
    nativeBalanceWei,
    explorerLink: explorerUrl(chainId, "address", address),
  };

  // ERC20 token balance if requested
  if (tokenQuery) {
    const tokenInfo = await resolveToken(tokenQuery, chainId);
    if (!tokenInfo) err(`Token "${tokenQuery}" not found on chain ${chainId}`);

    // balanceOf(address) selector: 0x70a08231 + padded address
    const paddedAddr = address.toLowerCase().replace("0x", "").padStart(64, "0");
    const callData = `0x70a08231${paddedAddr}`;

    const callFn = client.callContract?.bind(client) || client.call?.bind(client);
    if (!callFn) err(`Client for chain ${chainId} doesn't support contract calls`);
    const tokenResult = await callFn({ to: tokenInfo.address, data: callData });
    if (!tokenResult.success) err(`Token balance call failed: ${JSON.stringify(tokenResult.errors)}`);

    const tokenBalance = formatTokenBalance(tokenResult.data, tokenInfo.decimals);
    output.token = {
      symbol: tokenInfo.symbol,
      name: tokenInfo.name,
      address: tokenInfo.address,
      decimals: tokenInfo.decimals,
      balance: `${tokenBalance} ${tokenInfo.symbol}`,
      balanceRaw: hexToDecimal(tokenResult.data),
    };
  }

  out(output);
}

async function resolveToken(query, chainId) {
  try {
    const data = await fetchMetadata(chainToTokenPath(chainId));
    const q = query.toLowerCase();
    const isAddr = q.startsWith("0x") && q.length === 42;
    return data.tokens.find(t =>
      isAddr ? t.address.toLowerCase() === q : t.symbol.toLowerCase() === q
    ) || null;
  } catch {
    return null;
  }
}

async function cmdBlock(blockId, chainInput, privateOnly) {
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  let result;
  if (!blockId || blockId === "latest") {
    result = await client.getBlockByNumber("latest", false);
  } else if (blockId.startsWith("0x") && blockId.length === 66) {
    result = await client.getBlockByHash(blockId, false);
  } else {
    const hex = "0x" + parseInt(blockId, 10).toString(16);
    result = await client.getBlockByNumber(hex, false);
  }

  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);
  if (!result.data) err(`Block not found: ${blockId}`);

  const formatted = formatBlock(result.data);
  formatted.explorerLink = explorerUrl(chainId, "block", formatted.number);
  out(formatted);
}

async function cmdTx(txHash, chainInput, privateOnly) {
  if (!txHash || !txHash.startsWith("0x")) err("Usage: tx <0xhash> [--chain <chain>]");
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  const result = await client.getTransactionByHash(txHash);
  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);
  if (!result.data) err(`Transaction not found: ${txHash}`);

  const formatted = formatTx(result.data);
  formatted.explorerLink = explorerUrl(chainId, "tx", txHash);
  out(formatted);
}

async function cmdReceipt(txHash, chainInput, privateOnly) {
  if (!txHash || !txHash.startsWith("0x")) err("Usage: receipt <0xhash> [--chain <chain>]");
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  const result = await client.getTransactionReceipt(txHash);
  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);
  if (!result.data) err(`Receipt not found: ${txHash}`);

  // Try to decode event topics from metadata
  const formatted = formatReceipt(result.data);
  try {
    const events = await fetchMetadata("events/evm/1/common.json");
    for (const log of formatted.logs) {
      if (log.topics && log.topics[0] && events[log.topics[0]]) {
        log.eventName = events[log.topics[0]].event;
        log.eventDescription = events[log.topics[0]].description;
      }
    }
  } catch { /* skip event decoding */ }

  formatted.explorerLink = explorerUrl(chainId, "tx", txHash);
  out(formatted);
}

async function cmdGas(chainInput, privateOnly) {
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  const [gasPriceResult, priorityResult] = await Promise.allSettled([
    client.gasPrice(),
    client.maxPriorityFeePerGas(),
  ]);

  const output = { chainId };

  if (gasPriceResult.status === "fulfilled" && gasPriceResult.value.success) {
    output.gasPrice = `${gweiFromWei(gasPriceResult.value.data).toFixed(4)} gwei`;
    output.gasPriceWei = hexToDecimal(gasPriceResult.value.data);
  }

  if (priorityResult.status === "fulfilled" && priorityResult.value.success) {
    output.maxPriorityFeePerGas = `${gweiFromWei(priorityResult.value.data).toFixed(4)} gwei`;
  }

  // Try to get latest block for baseFee
  try {
    const blockResult = await client.getBlockByNumber("latest", false);
    if (blockResult.success && blockResult.data?.baseFeePerGas) {
      output.baseFee = `${gweiFromWei(blockResult.data.baseFeePerGas).toFixed(4)} gwei`;
      output.blockNumber = hexToDecimal(blockResult.data.number);
    }
  } catch { /* skip */ }

  out(output);
}

async function cmdCall(to, data, chainInput, blockTag, privateOnly) {
  if (!to || !data) err("Usage: call <to_address> <calldata_hex> [--chain <chain>] [--block <tag>]");
  const { client } = await getEvmClient(chainInput || "ethereum", privateOnly);

  const callFn = client.callContract?.bind(client) || client.call?.bind(client);
  if (!callFn) err(`Client doesn't support contract calls`);
  const result = await callFn({ to, data }, blockTag || "latest");
  if (!result.success) err(`Call failed: ${JSON.stringify(result.errors)}`);

  out({ to, data, blockTag: blockTag || "latest", result: result.data });
}

async function cmdLogs(chainInput, address, topics, fromBlock, toBlock, privateOnly) {
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  const filter = {};
  if (address) filter.address = address;
  if (topics && topics.length > 0) filter.topics = topics;
  filter.fromBlock = fromBlock || "latest";
  filter.toBlock = toBlock || "latest";

  const result = await client.getLogs(filter);
  if (!result.success) err(`getLogs failed: ${JSON.stringify(result.errors)}`);

  const logs = (result.data || []).slice(0, 50).map(log => ({
    address: log.address,
    blockNumber: hexToDecimal(log.blockNumber),
    transactionHash: log.transactionHash,
    topics: log.topics,
    data: log.data === "0x" ? "(empty)" : log.data.length > 138 ? `${log.data.slice(0, 138)}...` : log.data,
    explorerLink: explorerUrl(chainId, "tx", log.transactionHash),
  }));

  out({ count: logs.length, truncated: (result.data || []).length > 50, logs });
}

async function cmdCode(address, chainInput, privateOnly) {
  if (!address) err("Usage: code <address> [--chain <chain>]");
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  const result = await client.getCode(address);
  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);

  const code = result.data;
  const isEmpty = !code || code === "0x" || code === "0x0";
  out({
    address,
    isContract: !isEmpty,
    codeSize: isEmpty ? 0 : (code.length - 2) / 2,
    code: isEmpty ? "(EOA — no code)" : code.length > 200 ? `${code.slice(0, 200)}... (${(code.length - 2) / 2} bytes)` : code,
    explorerLink: explorerUrl(chainId, "address", address),
  });
}

async function cmdNonce(address, chainInput, privateOnly) {
  if (!address) err("Usage: nonce <address> [--chain <chain>]");
  const { client, chainId } = await getEvmClient(chainInput || "ethereum", privateOnly);

  const result = await client.getTransactionCount(address);
  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);

  out({ address, nonce: hexToDecimal(result.data), explorerLink: explorerUrl(chainId, "address", address) });
}

// ── ENS resolution ──────────────────────────────────────────────────────────

async function resolveENS(name) {
  if (!name.endsWith(".eth")) return name;

  // ENS registry on Ethereum mainnet
  // namehash the name, then call resolver
  const { client } = await getEvmClient("ethereum");

  // Use the ENS Universal Resolver at 0xce01f8eee7E479C928F8919abD53E553a36CeF67
  const UNIVERSAL_RESOLVER = "0xce01f8eee7E479C928F8919abD53E553a36CeF67";

  // Encode the DNS name
  const labels = name.split(".");
  let dnsName = "0x";
  for (const label of labels) {
    const len = label.length.toString(16).padStart(2, "0");
    const hex = Buffer.from(label).toString("hex");
    dnsName += len + hex;
  }
  dnsName += "00"; // null terminator

  // resolve(bytes name, uint256 coinType) — but simpler: use addr(bytes32 node)
  // Actually, use the universal resolver's resolve(bytes,bytes) function
  // Selector: 0x9061b923 = resolve(bytes name, bytes data)
  // data = addr(bytes32) selector 0x3b3b57de + namehash

  // Compute namehash
  let node = "0000000000000000000000000000000000000000000000000000000000000000";
  for (let i = labels.length - 1; i >= 0; i--) {
    // keccak256 of label — we need to use eth_call with sha3
    const labelHex = Buffer.from(labels[i]).toString("hex");
    const labelHashResult = await client.sha3("0x" + labelHex);
    if (!labelHashResult.success) return name; // fallback
    const labelHash = labelHashResult.data.slice(2);
    // namehash = keccak256(parentHash + labelHash)
    const combined = "0x" + node + labelHash;
    const nodeResult = await client.sha3(combined);
    if (!nodeResult.success) return name;
    node = nodeResult.data.slice(2);
  }

  // Now call resolver: addr(bytes32 node) = 0x3b3b57de + node
  const addrCall = "0x3b3b57de" + node;

  // Encode for universal resolver: resolve(bytes dnsName, bytes data)
  // But that's complex ABI encoding. Let's try simpler: directly query the ENS registry
  // ENS Registry: 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e
  // resolver(bytes32 node) = 0x0178b8bf + node
  const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
  const callFn = client.callContract?.bind(client) || client.call?.bind(client);

  const resolverResult = await callFn({ to: ENS_REGISTRY, data: "0x0178b8bf" + node });
  if (!resolverResult.success || !resolverResult.data || resolverResult.data === "0x" + "0".repeat(64)) {
    return name; // no resolver
  }
  const resolverAddr = "0x" + resolverResult.data.slice(26);

  // Call addr(bytes32) on the resolver
  const addrResult = await callFn({ to: resolverAddr, data: addrCall });
  if (!addrResult.success || !addrResult.data || addrResult.data === "0x" + "0".repeat(64)) {
    return name;
  }

  return "0x" + addrResult.data.slice(26);
}

// ── Multi-chain balance ─────────────────────────────────────────────────────

async function cmdMultiBalance(address, privateOnly) {
  const networksData = await fetchMetadata("networks.json");
  const evmChains = networksData.networks.filter(n => n.type === "evm" && !n.isTestnet);

  const results = [];
  const promises = evmChains.map(async (network) => {
    try {
      const rpcData = await fetchMetadata(chainToRpcPath(network.chainId));
      let endpoints = rpcData.endpoints.filter(e => e.isPublic);
      if (privateOnly) endpoints = endpoints.filter(e => e.tracking === "none");
      const order = { none: 0, limited: 1, unspecified: 2, yes: 3 };
      endpoints.sort((a, b) => (order[a.tracking] ?? 9) - (order[b.tracking] ?? 9));
      const rpcUrls = endpoints.slice(0, 3).map(e => e.url);
      if (rpcUrls.length === 0) return;

      const client = ClientFactory.createClient(network.chainId, { type: "fallback", rpcUrls });
      const result = await client.getBalance(address);
      if (result.success) {
        const balance = weiToEth(result.data);
        results.push({
          chain: network.shortName,
          chainId: network.chainId,
          currency: network.currency,
          balance: `${balance} ${network.currency}`,
          balanceRaw: hexToDecimal(result.data),
          hasBalance: balance > 0,
        });
      }
    } catch { /* skip failed chains */ }
  });

  await Promise.all(promises);

  // Sort: chains with balance first, then alphabetical
  results.sort((a, b) => {
    if (a.hasBalance !== b.hasBalance) return b.hasBalance ? 1 : -1;
    return a.chain.localeCompare(b.chain);
  });

  // Add per-chain explorer links
  for (const r of results) {
    r.explorerLink = explorerUrl(r.chainId, "address", address);
  }

  out({ address, chains: results.length, balances: results });
}

// ── Bitcoin client factory ──────────────────────────────────────────────────

const BITCOIN_MAINNET = "bip122:000000000019d6689c085ae165831e93";
const BTC_REST_API = "https://mempool.space/api"; // fallback for address lookups

async function getBtcClient() {
  const rpcData = await fetchMetadata("rpcs/btc/mainnet.json");
  // Filter for JSON-RPC compatible endpoints (exclude REST-only APIs)
  const jsonRpcEndpoints = rpcData.endpoints
    .filter(e => e.isPublic && !e.url.includes("mempool.space") && !e.url.includes("blockstream") && !e.url.includes("blockchain.info"))
    .map(e => e.url);

  // If no JSON-RPC endpoints found, try all of them (some may work)
  const rpcUrls = jsonRpcEndpoints.length > 0
    ? jsonRpcEndpoints
    : rpcData.endpoints.filter(e => e.isPublic).map(e => e.url);

  return ClientFactory.createClient(BITCOIN_MAINNET, { type: "fallback", rpcUrls });
}

function satsToBtc(sats) {
  return (Number(sats) / 1e8).toFixed(8);
}

function btcToSats(btc) {
  return Math.round(Number(btc) * 1e8);
}

async function cmdBtcInfo() {
  const client = await getBtcClient();

  const [countRes, hashRes, mempoolRes, feeRes] = await Promise.all([
    client.getBlockCount(),
    client.getBestBlockHash(),
    client.getMempoolInfo(),
    client.estimateSmartFee(6),
  ]);

  if (!countRes.success) err(`RPC error: ${JSON.stringify(countRes.errors)}`);

  // Get tip block details
  const blockRes = await client.getBlock(hashRes.data, 1);
  const b = blockRes.data;
  const m = mempoolRes.data;

  out({
    height: countRes.data,
    bestBlockHash: hashRes.data,
    timestamp: new Date(b.time * 1000).toISOString(),
    difficulty: b.difficulty,
    mempool: {
      txCount: m.size,
      sizeMB: (m.bytes / 1e6).toFixed(2),
      totalFeeBTC: m.total_fee?.toFixed(8) || "unknown",
      mempoolMinFee: `${btcToSats(m.mempoolminfee)} sat/vB`,
    },
    feeEstimate: feeRes.data ? {
      feeRate: `${btcToSats(feeRes.data.feerate)} sat/vB`,
      blocks: feeRes.data.blocks,
    } : null,
  });
}

async function cmdBtcBlock(blockId) {
  const client = await getBtcClient();

  let hash;
  if (!blockId || blockId === "latest") {
    const res = await client.getBestBlockHash();
    if (!res.success) err(`RPC error: ${JSON.stringify(res.errors)}`);
    hash = res.data;
  } else if (blockId.length === 64) {
    hash = blockId;
  } else {
    const height = parseInt(blockId, 10);
    if (isNaN(height)) err(`Invalid block identifier: ${blockId}`);
    const res = await client.getBlockHash(height);
    if (!res.success) err(`RPC error: ${JSON.stringify(res.errors)}`);
    hash = res.data;
  }

  const result = await client.getBlock(hash, 1);
  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);
  const b = result.data;

  out({
    hash: b.hash,
    height: b.height,
    timestamp: new Date(b.time * 1000).toISOString(),
    txCount: b.nTx,
    size: `${(b.size / 1024).toFixed(1)} KB`,
    weight: `${(b.weight / 1024).toFixed(1)} KWU`,
    difficulty: b.difficulty,
    nonce: b.nonce,
    version: b.version,
    merkleRoot: b.merkleroot,
    previousBlockHash: b.previousblockhash || null,
    medianTime: new Date(b.mediantime * 1000).toISOString(),
    confirmations: b.confirmations,
    explorerLink: explorerUrl("btc/mainnet", "block", b.hash),
  });
}

async function cmdBtcTx(txid) {
  if (!txid) err("Usage: btc-tx <txid>");
  const client = await getBtcClient();

  const result = await client.getRawTransaction(txid, true);
  if (!result.success) err(`RPC error: ${JSON.stringify(result.errors)}`);
  const tx = result.data;

  // Calculate total output value
  const totalOut = tx.vout.reduce((s, v) => s + (v.value || 0), 0);

  out({
    txid: tx.txid,
    confirmed: !!tx.blockhash,
    blockHash: tx.blockhash || null,
    confirmations: tx.confirmations || 0,
    timestamp: tx.time ? new Date(tx.time * 1000).toISOString() : null,
    version: tx.version,
    size: `${tx.size} bytes`,
    vsize: `${tx.vsize} vbytes`,
    weight: `${tx.weight} WU`,
    inputs: tx.vin.length,
    outputs: tx.vout.length,
    totalOutput: `${totalOut.toFixed(8)} BTC`,
    isCoinbase: tx.vin.length > 0 && !!tx.vin[0].coinbase,
    vin: tx.vin.slice(0, 5).map(v => ({
      txid: v.txid ? `${v.txid.slice(0, 16)}...` : "(coinbase)",
      vout: v.vout,
      isCoinbase: !!v.coinbase,
    })),
    vout: tx.vout.slice(0, 5).map(v => ({
      n: v.n,
      value: `${v.value.toFixed(8)} BTC`,
      type: v.scriptPubKey?.type,
      address: v.scriptPubKey?.address || null,
    })),
    truncated: tx.vin.length > 5 || tx.vout.length > 5,
    explorerLink: explorerUrl("btc/mainnet", "tx", tx.txid),
  });
}

async function cmdBtcMempool() {
  const client = await getBtcClient();

  const [mempoolRes, feeRes] = await Promise.all([
    client.getMempoolInfo(),
    client.estimateSmartFee(6),
  ]);

  if (!mempoolRes.success) err(`RPC error: ${JSON.stringify(mempoolRes.errors)}`);
  const m = mempoolRes.data;

  // Get raw mempool txids (limited)
  const rawRes = await client.getRawMempool(false);
  const txids = rawRes.success ? (rawRes.data || []).slice(0, 5) : [];

  out({
    txCount: m.size,
    sizeMB: (m.bytes / 1e6).toFixed(2),
    totalFeeBTC: m.total_fee?.toFixed(8) || "unknown",
    mempoolMinFee: `${btcToSats(m.mempoolminfee)} sat/vB`,
    minRelayFee: `${btcToSats(m.minrelaytxfee)} sat/vB`,
    loaded: m.loaded,
    maxMempoolMB: (m.maxmempool / 1e6).toFixed(0),
    feeEstimate: feeRes.data ? {
      feeRate: `${btcToSats(feeRes.data.feerate)} sat/vB`,
      blocks: feeRes.data.blocks,
    } : null,
    recentTxids: txids.map(t => `${t.slice(0, 16)}...`),
  });
}

async function cmdBtcFee() {
  const client = await getBtcClient();

  // estimateSmartFee for different confirmation targets
  const targets = [1, 3, 6, 12, 25];
  const results = await Promise.all(
    targets.map(t => client.estimateSmartFee(t))
  );

  const fees = {};
  const labels = ["nextBlock", "3blocks", "6blocks", "12blocks", "25blocks"];
  targets.forEach((t, i) => {
    if (results[i].success && results[i].data?.feerate) {
      fees[labels[i]] = `${btcToSats(results[i].data.feerate)} sat/vB`;
    }
  });

  out({ ...fees, note: "Fee estimates via estimateSmartFee (Bitcoin Core)" });
}

async function cmdBtcAddress(address) {
  if (!address) err("Usage: btc-address <address>");
  // Address balance requires an indexer — Bitcoin Core RPC doesn't support it natively.
  // Fall back to mempool.space REST API for this specific query.
  const url = `${BTC_REST_API}/address/${address}`;
  const res = await fetch(url);
  if (!res.ok) err(`Address lookup failed: ${res.status}`);
  const data = await res.json();

  const funded = data.chain_stats.funded_txo_sum + data.mempool_stats.funded_txo_sum;
  const spent = data.chain_stats.spent_txo_sum + data.mempool_stats.spent_txo_sum;
  const balance = funded - spent;

  out({
    address: data.address,
    balance: `${satsToBtc(balance)} BTC`,
    balanceSats: balance,
    totalReceived: `${satsToBtc(funded)} BTC`,
    totalSent: `${satsToBtc(spent)} BTC`,
    txCount: data.chain_stats.tx_count + data.mempool_stats.tx_count,
    confirmedTxCount: data.chain_stats.tx_count,
    unconfirmedTxCount: data.mempool_stats.tx_count,
    utxoCount: data.chain_stats.funded_txo_count - data.chain_stats.spent_txo_count,
    explorerLink: explorerUrl("btc/mainnet", "address", address),
  });
}

// ── CLI router ──────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log(`openscan-crypto CLI

Metadata commands:
  networks                              List supported networks
  rpcs <chain> [--private]              List RPC endpoints
  token <symbol|address> [--chain]      Look up token info
  events [--chain <chain>]              List known event signatures
  decode-event <topic>                  Decode event topic hash
  addresses [--chain <chain>]           List labeled addresses
  profile <type> <id>                   Show profile

EVM queries (use --chain <chain>, default: ethereum, supports .eth names):
  balance <address> [--token <sym>]     Native + ERC20 balance
  multi-balance <address>               Balance across ALL chains
  block [number|hash|latest]            Block info
  tx <0xhash>                           Transaction details
  receipt <0xhash>                      Transaction receipt + logs
  gas                                   Gas price + base fee
  call <to> <data>  [--block <tag>]     eth_call (read contract)
  logs --address <addr> [--topic <t>]   Event logs (--from/--to blocks)
  code <address>                        Contract code / EOA check
  nonce <address>                       Transaction count

Bitcoin queries (mempool.space REST API):
  btc-info                              Blockchain overview + mempool + fees
  btc-block [height|hash|latest]        Block details
  btc-tx <txid>                         Transaction details
  btc-mempool                           Mempool state + recent txs
  btc-fee                               Recommended fee rates
  btc-address <address>                 Address balance + tx count

Flags: --chain <chain>, --private (tracking:none RPCs only)
Chain aliases: ethereum/eth, bitcoin/btc, arbitrum/arb, optimism/op, base, polygon/matic, bnb/bsc
`);
    return;
  }

  const cmd = args[0];
  const flagIndex = (flag) => args.indexOf(flag);
  const flagValue = (flag) => {
    const idx = flagIndex(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  };
  const hasFlag = (flag) => args.includes(flag);

  try {
    switch (cmd) {
      case "networks":
        await cmdNetworks();
        break;

      case "rpcs":
        if (!args[1]) err("Usage: rpcs <chain> [--private]");
        await cmdRpcs(args[1], hasFlag("--private"));
        break;

      case "token":
        if (!args[1]) err("Usage: token <symbol|address> [--chain <chain>]");
        await cmdToken(args[1], flagValue("--chain"));
        break;

      case "events":
        await cmdEvents(flagValue("--chain"));
        break;

      case "decode-event":
        if (!args[1]) err("Usage: decode-event <topic_hash>");
        await cmdDecodeEvent(args[1]);
        break;

      case "addresses":
        await cmdAddresses(flagValue("--chain"));
        break;

      case "profile":
        if (!args[1] || !args[2]) err("Usage: profile <type> <id>");
        await cmdProfile(args[1], args[2]);
        break;

      // ── Phase 2: EVM queries ──
      case "balance":
        if (!args[1]) err("Usage: balance <address|name.eth> [--token <symbol>] [--chain <chain>] [--private]");
        await cmdBalance(await resolveENS(args[1]), flagValue("--chain"), flagValue("--token"), hasFlag("--private"));
        break;

      case "multi-balance":
        if (!args[1]) err("Usage: multi-balance <address|name.eth> [--private]");
        await cmdMultiBalance(await resolveENS(args[1]), hasFlag("--private"));
        break;

      case "block":
        await cmdBlock(args[1] || "latest", flagValue("--chain"), hasFlag("--private"));
        break;

      case "tx":
        if (!args[1]) err("Usage: tx <0xhash> [--chain <chain>]");
        await cmdTx(args[1], flagValue("--chain"), hasFlag("--private"));
        break;

      case "receipt":
        if (!args[1]) err("Usage: receipt <0xhash> [--chain <chain>]");
        await cmdReceipt(args[1], flagValue("--chain"), hasFlag("--private"));
        break;

      case "gas":
        await cmdGas(flagValue("--chain"), hasFlag("--private"));
        break;

      case "call":
        if (!args[1] || !args[2]) err("Usage: call <to_address> <calldata> [--chain <chain>] [--block <tag>]");
        await cmdCall(args[1], args[2], flagValue("--chain"), flagValue("--block"), hasFlag("--private"));
        break;

      case "logs": {
        const address = flagValue("--address");
        const topic = flagValue("--topic");
        const fromBlock = flagValue("--from");
        const toBlock = flagValue("--to");
        await cmdLogs(flagValue("--chain"), address, topic ? [topic] : [], fromBlock, toBlock, hasFlag("--private"));
        break;
      }

      case "code":
        if (!args[1]) err("Usage: code <address|name.eth> [--chain <chain>]");
        await cmdCode(await resolveENS(args[1]), flagValue("--chain"), hasFlag("--private"));
        break;

      case "nonce":
        if (!args[1]) err("Usage: nonce <address|name.eth> [--chain <chain>]");
        await cmdNonce(await resolveENS(args[1]), flagValue("--chain"), hasFlag("--private"));
        break;

      // ── Phase 3: Bitcoin queries ──
      case "btc-info":
        await cmdBtcInfo();
        break;

      case "btc-block":
        await cmdBtcBlock(args[1]);
        break;

      case "btc-tx":
        if (!args[1]) err("Usage: btc-tx <txid>");
        await cmdBtcTx(args[1]);
        break;

      case "btc-mempool":
        await cmdBtcMempool();
        break;

      case "btc-fee":
        await cmdBtcFee();
        break;

      case "btc-address":
        if (!args[1]) err("Usage: btc-address <address>");
        await cmdBtcAddress(args[1]);
        break;

      default:
        err(`Unknown command: ${cmd}. Run without arguments for help.`);
    }
  } catch (e) {
    err(e.message);
  }
}

main();
