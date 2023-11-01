import react from 'react'
import './index.less'
import { initWasm } from '@trustwallet/wallet-core'
export default function App() {

  async function generate() {
    const {HDWallet, CoinType} = await initWasm();
     const wallet = HDWallet.create(128, "");
     var tiaAddress = wallet.getAddressForCoin(CoinType.tia);
     console.log(`celestia :${tiaAddress}`);
  }

  return (
    <div className="app-d4cae53d-37d2-128d-7a5e-b70f778f6715">
      base config
      <button onClick={generate}>222 Wallet</button>
    </div>
  )
}