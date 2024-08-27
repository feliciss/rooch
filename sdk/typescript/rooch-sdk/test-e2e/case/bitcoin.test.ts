// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { TestBox } from '../setup.js'
import { BitcoinNetowkType } from '../../src'

describe('Bitcoin Assets API', () => {
  let testBox: TestBox

  beforeAll(async () => {
    testBox = TestBox.setup()
    await testBox.loadBitcoinEnv()
    await testBox.loadORDEnv()
    await testBox.loadRoochEnv()
  })

  afterAll(() => {
    testBox.unloadContainer()
  })

  it('query utxo should be success', async () => {
    const addr = testBox.keypair.getSchnorrPublicKey().buildAddress(1, BitcoinNetowkType.Regtest).toStr()
    console.log(addr)
    const result = await testBox.bitcoinContainer?.executeRpcCommand('generatetoaddress', [
      '50',
      addr,
    ])
    expect(result).toBeDefined()

    // rooch indexer
    await testBox.delay(10)

    const utxos = await testBox.getClient().queryUTXO({
      filter: {
        owner: addr,
      },
    })

    expect(utxos.data.length).toBeGreaterThan(0)
  })

  it('query inscriptions should be success', async () => {
    // init wallet
    let result = await testBox.ordContainer?.execCmd('wallet create')
    expect(result!.exitCode).eq(0)
    result = await testBox.ordContainer?.execCmd('wallet receive')
    expect(result!.exitCode).eq(0)
    const addr = JSON.parse(result!.output).addresses[0]

    // mint utxo
    result = await testBox.bitcoinContainer?.executeRpcCommand('generatetoaddress', ['101', addr])
    expect(result).toBeDefined()

    // Then sleep: "10" wait ord sync and index
    await testBox.delay(10)
    result = await testBox.ordContainer?.execCmd('wallet balance')
    const balance = JSON.parse(result!.output).total
    expect(balance).eq(5000000000)

    // create a inscription
    testBox.shell(
      `echo "{"p":"brc-20","op":"mint","tick":"Rooch","amt":"1"}">/${testBox.ordContainer!.getHostDataPath()}/hello.txt`,
    )
    result = await testBox.ordContainer?.execCmd(
      `wallet inscribe --fee-rate 1 --file /data/hello.txt --destination ${addr}`,
    )
    expect(result!.exitCode).eq(0)

    // mint utxo
    result = await testBox.bitcoinContainer?.executeRpcCommand('generatetoaddress', ['1', addr])
    expect(result).toBeDefined()

    // wait rooch indexer
    await testBox.delay(10)

    const utxos = await testBox.getClient().queryUTXO({
      filter: {
        owner: addr,
      },
    })
    expect(utxos.data.length).toBeGreaterThan(0)

    // first make sure don’t break
    try {
      const inscriptions = await testBox.getClient().queryInscriptions({
        filter: {
          owner: addr,
        },
      })
      // TODO: check inscriptions result
      expect(inscriptions).toBeDefined()
    } catch (e) {
      expect(e).toBeUndefined()
    }
  })
})