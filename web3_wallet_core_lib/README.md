Trust Wallet Core is an open source, cross platform and cross blockchain library, it adds beta support for WebAssembly recently, You can try it out now:

```js
npm install @trustwallet/wallet-core
```

Documentation will be added to [developer.trustwallet.com](https://developer.trustwallet.com/wallet-core) later, please check out [tests](https://github.com/trustwallet/wallet-core/tree/master/wasm/tests) here for API usages.

# 说明
web3_wallet_core_lib 是浏览器插件使用的 wallet-core lib，来源是[wallet-core](https://github.com/trustwallet/wallet-core), 根据 fork 的[分支](https://github.com/weixuefeng/wallet-core/tree/build-web3-wallet)进行修改编译以适配
浏览器插件使用。

## 如何构建
原 `wallet-core` 编译的产物不支持浏览器使用，[修改内容参考](https://github.com/trustwallet/wallet-core/discussions/3193#discussioncomment-6196161),
构建文档参考 [developer.trustwallet.com](https://developer.trustwallet.com/wallet-core)

## 如何在浏览器插件中使用
[demo](https://github.com/weixuefeng/wallet-core-with-vite)
- 修改 `manifest.json`中 `content_security_policy` 配置， 增加 `wasm-unsafe-eval`
- 将 `wallet-core.wasm` 放到项目根目录下。有更好的方式可以继续讨论。

- 使用步骤:
 	- 复制项目到自己的项目中
	- `yarn install ./web3_wallet_core_lib`
	- 修改对应 manifest.json 支持 wasm
	- 如有需要，调整 wallet-core.wasm 位置，以便浏览器插件能够加载
	- 如何使用可以参考上述demo项目。
