import react from 'react'
import './index.less'
import {TW, initWasm} from '@trustwallet/wallet-core'
export default function App() {

  async function generate() {
    const {HDWallet, CoinType} = await initWasm();
     const wallet = HDWallet.create(128, "");
     console.log(`type:${CoinType.bitcoin.value}`)
     console.log(wallet.mnemonic());
     var bitcoinAddress = wallet.getAddressForCoin(CoinType.bitcoin);
     console.log(`bitcoinAddress:${bitcoinAddress}`);
  }

  return (
    <div className="app-d4cae53d-37d2-128d-7a5e-b70f778f6715">
      base config
      <button onClick={generate}>CreateBit Wallet</button>
    </div>
  )
}