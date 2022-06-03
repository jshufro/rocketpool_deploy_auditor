const assert = require('assert');
const Web3 = require('web3');
const config = require('config');
const debug = require('debug')('audit');
const util = require('ethereumjs-util');
const etherscan = require('etherscan-api').init(config.get('etherscan_key'))

const deployer = '0x0ccf14983364a7735d369879603930afe10df21e';
const rocketStorage = '0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46';
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
    rocketStorageTxs = await getTxsForAddr(rocketStorage, await web3.eth.getBlockNumber());

    debug(`Found ${rocketStorageTxs.length} transactions`);
    const setBool = web3.utils.sha3("setBool(bytes32,bool)").slice(0,10);
    debug(`Filtering for inputs with ${setBool}`);

    setBoolCalls = rocketStorageTxs.filter(tx => tx.input.startsWith(setBool));
    debug(`Found ${setBoolCalls.length} calls to setBool`);
    assert(setBoolCalls.length > 0);
  });

  it(`Should validate that the calls to setBool all have parameter 1 matching the hash of a deployed contract as seen by etherscan`, async function() {
    var allowedSetBoolArgs = new Set();
    for (address of contractsEtherscan) {
      const arg = Buffer.concat([Buffer.from("contract.exists"), util.toBuffer(address)]);
      const hashed = util.bufferToHex(util.keccak256(arg));
      allowedSetBoolArgs.add(hashed);
    }
    debug(`Mapped to ${allowedSetBoolArgs.size} whitelisted setBool arguments.`);

    var matched = 0;
    var unmatched = 0;
    for (call of setBoolCalls) {
      /* Trim off the function selector and value to get the hash */
      const _key = "0x"+call.input.slice(10).slice(0, 64)
      if (allowedSetBoolArgs.has(_key)) {
        matched++;
      } else {
        unmatched++;
        debug(`Unmatched call to setBool with _key ${_key}`);
      }
    }

    debug(`${matched} matched - ${unmatched} unmatched`)
    assert.equal(unmatched, 0);
  });

  it(`Should validate that the calls to setBool all have parameter 1 matching the hash of any possible contract deployed by ${deployer}`, async function() {
    var allowedSetBoolArgs = new Set();
    for (address of contractsPossible) {
      const arg = Buffer.concat([Buffer.from("contract.exists"), util.toBuffer(address)]);
      const hashed = util.bufferToHex(util.keccak256(arg));
      allowedSetBoolArgs.add(hashed);
    }
    debug(`Mapped to ${allowedSetBoolArgs.size} whitelisted setBool arguments.`);

    var matched = 0;
    var unmatched = 0;
    for (call of setBoolCalls) {
      /* Trim off the function selector and value to get the hash */
      const _key = "0x"+call.input.slice(10).slice(0, 64)
      if (allowedSetBoolArgs.has(_key)) {
        matched++;
      } else {
        unmatched++;
        debug(`Unmatched call to setBool with _key ${_key}`);
      }
    }

    debug(`${matched} matched - ${unmatched} unmatched`)
    assert.equal(unmatched, 0);
  });

  it(`Should validate that setDeployedStatus() was called`, function() {
    const setDeployedStatus = web3.utils.sha3("setDeployedStatus()").slice(0,10);

    const setDeployedStatusTx = rocketStorageTxs.find(tx => { return tx.input.startsWith(setDeployedStatus) });
    assert(setDeployedStatusTx);
    assert.equal(setDeployedStatusTx.isError, '0');
    assert.equal(setDeployedStatusTx.txreceipt_status, '1');
  });

  after(async function() {
    await web3.currentProvider.connection.close();
  });
});
