# Rocket Pool Auditor

This repo will check that each call to setBool in Rocket Storage prior to the setDeployedStatus() call was in fact
done to set `contract.exists` as specified in the [Rocket Pool deploy script](https://github.com/rocket-pool/rocketpool/blob/master/migrations/2_deploy_contracts.js).

In summary, this is what it does:
1. Grab all contract creation transactions from the guardian from etherscan
2. Grab the highest nonce for the guardian wallet and generate all possible contract addresses it could have created
3. Grab all the transactions invoking `setBool` on the Storage contract
4. Validate that every call to setBool matches a contract from step 1
5. Validate that every call to setBool matches an address from step 2
6. Validate that steps 4 and 5 have the same exact contract address list
7. Validate setDeployedStatus() was called
8. Grab all calls to the bootstrapUpgrade function in RocketDaoNodeTrusted contract and add the new contracts to the list to be verified, _except_ the old RPL token contract (which doesn't seem to be available in the git repo, but is trivially auditable by hand)
9. Download the source code (from etherscan) for all contracts deployed and compare them the contracts in tag v1.0.0 and v1.0.0-pre (in the github repository).

It requires a web3 provider (execution client) and an Etherscan api token.

## Setup
Clone the repo:
```
git clone https://github.com/jshufro/rocketpool_deploy_auditor.git
git submodule update --init
```

Create a config file:
```
cp config/default.json.example config/default.json
```

Edit that file to set a web3 provider URL and a Etherscan token.

Run
```
npm install
```
to install dependencies.

## Run the checks
Run `npm test` or `DEBUG=audit npm test` to run the checks.
