import react from 'react'
import './index.less'
import { initWasm } from '@trustwallet/wallet-core'
export default function App() {

  async function generate() {
    const {HDWallet, CoinType, HexCoding, Curve, PrivateKey, AnyAddress} = await initWasm();
    var hd = HDWallet.createWithMnemonic("mirror fiber cover curve media identify version balance panther world brother milk", "")
    //  const wallet = HDWallet.create(128, "");
     var tiaAddress = hd.getAddressForCoin(CoinType.sui);
     console.log("tia: ",tiaAddress)
     var valid = AnyAddress.isValid(tiaAddress, CoinType.sui)
     console.log(`sui :${valid}`);
  }

  return (
    <div className="app-d4cae53d-37d2-128d-7a5e-b70f778f6715">
      base config
      <button onClick={generate}>222 Wallet</button>
    </div>
  )
}