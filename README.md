# Rocket Pool Auditor

This repo will check that each call to setBool in Rocket Storage prior to the setDeployedStatus() call was in fact
done to set `contract.exists` as specified in the [Rocket Pool deploy script](https://github.com/rocket-pool/rocketpool/blob/master/migrations/2_deploy_contracts.js).

It requires a web3 provider (execution client) and an Etherscan api token.

## Setup
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
