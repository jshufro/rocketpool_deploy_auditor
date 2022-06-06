const fs = require('fs');
const assert = require('assert');
const Web3 = require('web3');
const config = require('config');
const debug = require('debug')('audit');
const util = require('ethereumjs-util');
const fetch = require('node-fetch');
const etherscanApiKey = config.get('etherscan_key');
const etherscan = require('etherscan-api').init(etherscanApiKey)

const deployer = '0x0ccf14983364a7735d369879603930afe10df21e';
const rocketStorage = '0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46';
const rocketDaoNodeTrusted = '0xb8e783882b11Ff4f6Cef3C501EA0f4b960152cc9';
const casper = "0x00000000219ab540356cBB839Cbe05303d7705Fa";
const minBlock = 12007727;

async function getTxsForAddr(address, currentBlockNumber) {
  /* Get all the transactions from etherscan */
  var txs = [];
  var page = 1;
  while (true) {
    debug(`Querying ${address} page ${page} from etherscan`);
    var resp;
    try {
      resp = await etherscan.account.txlist(address, minBlock, currentBlockNumber, page, 1000, "desc");
    } catch (e) {
      if (typeof(e) !== "string") {
        throw e;
      }

      if (e.startsWith('No transactions found')) {
        debug("No more txs to download");
        break;
      }

      throw e;
    }
    assert.equal(resp.status, '1');
    assert.equal(resp.message, 'OK');

    txs.push(...resp.result);
    page++;
  }

  return txs;
}

describe("Audit", function() {
  this.timeout(30000);
  var web3;

  var contractsEtherscan;
  before(async function() {
    web3 = await new Web3(config.get('web3provider'));
  });

  it(`Should retrieve all contract creation transactions for ${deployer} from etherscan`, async function() {
    // Get all the txs for the deployer from etherscan
    const txs = await getTxsForAddr(deployer, await web3.eth.getBlockNumber());
    // We only care about contract creation
    const creations = txs.filter(tx => {
      return tx.input.startsWith("0x60806040");
    });
    contractsEtherscan = new Set(creations.map(c => c.contractAddress));
    debug(`Etherscan had ${contractsEtherscan.size} contract creations`);
  });

  var contractsPossible;
  it(`Should generate all possible contract addresses given the current nonce of the deployer`, async function() {
    // Get the current nonce
    const nonce = await web3.eth.getTransactionCount(deployer);
    debug(`Deployer nonce is ${nonce}`);
    contractsPossible = new Set();
    for (var i = 0; i <= nonce; i++) {
      const address = util.bufferToHex(util.generateAddress(util.toBuffer(deployer), util.toBuffer(i)));
      contractsPossible.add(address);
    }
    debug(`Found ${contractsPossible.size} potential contract addresses`)

    debug(`Adding the casper contract ${casper} to potential targets`)
    contractsEtherscan.add(casper);
    contractsPossible.add(casper);
  });

  var setBoolCalls;
  var rocketStorageTxs;
  it(`Should fetch all the setBool txs for rocketStorage from etherscan`, async function() {
    /* Get all the setBool transactions from etherscan */
    const block = await web3.eth.getBlockNumber();
    rocketStorageTxs = await getTxsForAddr(rocketStorage, block);

    debug(`Found ${rocketStorageTxs.length} transactions`);
    const setBool = web3.utils.sha3("setBool(bytes32,bool)").slice(0,10);
    debug(`Filtering for inputs with ${setBool}`);

    setBoolCalls = rocketStorageTxs.filter(tx => tx.input.startsWith(setBool));
    debug(`Found ${setBoolCalls.length} calls to setBool`);
    assert(setBoolCalls.length > 0);
  });

  var etherscanSetBoolAddrs = [];
  it(`Should validate that the calls to setBool all have parameter 1 matching the hash of a deployed contract as seen by etherscan`, async function() {
    var allowedSetBoolArgs = {};
    for (address of contractsEtherscan) {
      const arg = Buffer.concat([Buffer.from("contract.exists"), util.toBuffer(address)]);
      const hashed = util.bufferToHex(util.keccak256(arg));
      allowedSetBoolArgs[hashed] = address;
    }
    debug(`Mapped to ${allowedSetBoolArgs.size} whitelisted setBool arguments.`);

    var matched = 0;
    var unmatched = 0;
    for (call of setBoolCalls) {
      /* Trim off the function selector and value to get the hash */
      const _key = "0x"+call.input.slice(10).slice(0, 64)
      if (allowedSetBoolArgs[_key] != undefined) {
        matched++;
        etherscanSetBoolAddrs.push(allowedSetBoolArgs[_key]);
      } else {
        unmatched++;
        debug(`Unmatched call to setBool with _key ${_key}`);
      }
    }

    debug(`${matched} matched - ${unmatched} unmatched`)
    assert.equal(unmatched, 0);
  });

  var inferredSetBoolAddrs = [];
  it(`Should validate that the calls to setBool all have parameter 1 matching the hash of any possible contract deployed by ${deployer}`, async function() {
    var allowedSetBoolArgs = {};
    for (address of contractsPossible) {
      const arg = Buffer.concat([Buffer.from("contract.exists"), util.toBuffer(address)]);
      const hashed = util.bufferToHex(util.keccak256(arg));
      allowedSetBoolArgs[hashed] = address;
    }
    debug(`Mapped to ${allowedSetBoolArgs.size} whitelisted setBool arguments.`);

    var matched = 0;
    var unmatched = 0;
    for (call of setBoolCalls) {
      /* Trim off the function selector and value to get the hash */
      const _key = "0x"+call.input.slice(10).slice(0, 64)
      if (allowedSetBoolArgs[_key] != undefined) {
        matched++;
        inferredSetBoolAddrs.push(allowedSetBoolArgs[_key]);
      } else {
        unmatched++;
        debug(`Unmatched call to setBool with _key ${_key}`);
      }
    }

    debug(`${matched} matched - ${unmatched} unmatched`)
    assert.equal(unmatched, 0);
  });

  it('Should verify that all the inferred contract addresses were captured by etherscan', async function() {
    assert.deepStrictEqual(inferredSetBoolAddrs, etherscanSetBoolAddrs);
  });

  it('Should validate that setDeployedStatus() was called', function() {
    const setDeployedStatus = web3.utils.sha3("setDeployedStatus()").slice(0,10);

    const setDeployedStatusTx = rocketStorageTxs.find(tx => { return tx.input.startsWith(setDeployedStatus) });
    assert(setDeployedStatusTx);
    assert.equal(setDeployedStatusTx.isError, '0');
    assert.equal(setDeployedStatusTx.txreceipt_status, '1');
  });

  var lastRequestTime;
  async function getContractCode(addr) {
    // etherscan-api doesn't support contract source code calls, so build the urls manually
    const url = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${addr}&apikey=${etherscanApiKey}`

    // etherscan api rate limits to 5 calls per second. Wait 0.22 seconds between calls.
    var now = new Date();
    if (lastRequestTime != undefined && now - lastRequestTime < 220) {
      await new Promise((resolve) => {
        setTimeout(resolve, now - lastRequestTime);
      });
    }
    lastRequestTime = new Date();
    const response = await fetch(url);

    const data = await response.json();

    if (data.message != 'OK')
      debug(data);

    assert.equal(data.message, 'OK');
    assert.equal(data.status, '1');

    // For some reason, the json response is an illegal object '{{ }}'. Slice off the odd bits.
    debug(`Downloading ${addr}`)
    if (data.result[0].SourceCode.startsWith('{{')) {
      return JSON.parse(data.result[0].SourceCode.slice(1,-1));
    }

    // If the response isn't json, it's the plain text source of the contract
    return data.result[0].SourceCode;
  }

  // inferredSetBoolAddrs is identical to the etherscan list iff the penultimate test passed
  var addrsToCheck = inferredSetBoolAddrs;
  it('Should fetch all the bootstrapUpgrade txs for Rocket Pool: Trusted Node from etherscan', async function() {
    /* Get all the setBool transactions from etherscan */
    const block = await web3.eth.getBlockNumber();
    upgradeTxs = await getTxsForAddr(rocketDaoNodeTrusted, block);

    debug(`Found ${upgradeTxs.length} transactions`);
    const bootstrapUpgrade = web3.utils.sha3("bootstrapUpgrade(string,string,string,address)").slice(0,10);
    debug(`Filtering for inputs with ${bootstrapUpgrade}`);

    const bootstrapUpgradeCalls = upgradeTxs.filter(tx => tx.input.startsWith(bootstrapUpgrade));
    debug(`Found ${bootstrapUpgradeCalls.length} calls to bootstrapUpgrade`);
    assert(bootstrapUpgrade.length > 0);

    const upgradeAddrs = new Set();
    for (tx of bootstrapUpgradeCalls) {
      const start = 10 + 64 * 3; // Beginning of the 4th parameter
      const addr = tx.input.slice(start + 24, start + 24 + 40);

      // Filter out txs with no new address
      if (addr == "0".repeat(40)) {
        continue;
      }

      debug(`Upgrade found with new contract at address ${addr}`);
      upgradeAddrs.add("0x"+addr);
    }
    addrsToCheck.push(... Array.from(upgradeAddrs));
  });

  var toVerify = [];
  it('Should download the contract source for all addresses that setBool received, except casper', async function() {
    var addrs = addrsToCheck.filter(a => a != casper); 

    debug(`Found ${addrs.length} contracts to validate`);

    // Download contract source code from etherscan for all contracts.
    var contracts = [];
    for (addr of addrs) {

      if (["0x6a032a901f17227b4db52937fb25f2523a529760"].includes(addr)) {
        debug(`Skipping ${addr}`);
        continue; //TODO Why is the source code different? 72 hours vs 5760 blocks in RocketDAOProtocolSettingsMinipool
      }

      if (["0xb4efd85c19999d84251304bda99e90b92300bd93"].includes(addr)) {
        debug(`Skipping ${addr}`);
        continue; //TODO Whither the OldRPL source? Do we care?
      }

      contracts.push({ 'addr': addr, 'resp': await getContractCode(addr)});
    }

    debug(`Downloaded ${Object.keys(contracts).length} contracts`)
    const skip = new Set(['@openzeppelin']);
    for (contract of contracts) {
      if (contract.resp.sources == undefined) {
        debug(contract);
      }
      for (path of Object.keys(contract.resp.sources)) {
        if (skip.has(path.split("/")[0])) {
          debug(`Skipping ${path}`);
          continue;
        }
        toVerify.push({ 'addr': contract.addr, 'path': path, 'code': contract.resp.sources[path].content });
      }
    }
  });

  var header;
  var header2;
  function removeHeadersAndCRLF(code) {
    if (header == undefined) {
      // Etherscan code has a header that is absent from github code. It is all comments, and a copy is in header.txt
      header = fs.readFileSync('header.txt').toString();
      // There's a different header for Eth 2.0 contracts
      header2 = fs.readFileSync('header2.txt').toString();
    }

    // Convert CR to LF
    var code = code.replace(/\r\n/g, '\n')

    // Trim the headers from the etherscan result before comparing.
    code = code.replace(header, "");
    code = code.replace(header2, "");

    return code;
  }

  function getUnverified(toVerify, files) {
    var mismatched = [];
    for (item of toVerify) {
      var etherscanCode = removeHeadersAndCRLF(item.code);

      debug(`Verifying ${item.path} at ${item.addr}`)
      if (files[item.path] != etherscanCode) {
        mismatched.push(item);
      }
    }
    return mismatched;
  }

  it('Should attempt to verify all the contracts against the first version of rocketpool, commit 67a64456397dc763b6831539221fdfb172d4335e', async function() {
    // Verify that each contracts entry has a sources array comprised of dependencies _or_ v1.0.0 contracts.
    const prefix = "rocketpool-67a644"; // Path prefix of submodule
    var files = {}
    // Read the files into memory
    for (item of toVerify) {
      if (files[item.path] == undefined) {
        const path = `${prefix}${item.path}`
        if (!fs.existsSync(path)) {
          continue;
        }
        files[item.path] = fs.readFileSync(path).toString();
      }
    }
    // Recreate toVerify with only the remaining unverified contracts
    toVerify = getUnverified(toVerify, files);
    debug(`${toVerify.length} items left to verify`);
  });

  it('Should attempt to verify all the contracts against the version 1.0.0 of rocketpool', async function() {
    // Verify that each contracts entry has a sources array comprised of dependencies _or_ v1.0.0 contracts.
    const prefix = "rocketpool-v1.0.0"; // Path prefix of submodule
    var files = {}
    // Read the files into memory
    for (item of toVerify) {
      if (files[item.path] == undefined) {
        const path = `${prefix}${item.path}`
        if (!fs.existsSync(path)) {
          continue;
        }
        files[item.path] = fs.readFileSync(path).toString();
      }
    }
    // Recreate toVerify with only the remaining unverified contracts
    toVerify = getUnverified(toVerify, files);
    debug(`${toVerify.length} items left to verify`);
  });

  it('Should have verified all the smart contracts', function() {
    if (toVerify.length > 0) {
      debug(toVerify.map(item => [item.path, item.addr]));
    }
    assert.deepStrictEqual(toVerify, []);
  });

  after(async function() {
    await web3.currentProvider.connection.close();
  });
});
