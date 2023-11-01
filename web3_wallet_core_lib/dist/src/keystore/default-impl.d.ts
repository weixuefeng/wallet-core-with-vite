import { WalletCore, CoinType, PrivateKey, StoredKey, StoredKeyEncryption } from "../wallet-core";
import * as Types from "./types";
export declare class Default implements Types.IKeyStore {
    private readonly core;
    private readonly storage;
    constructor(core: WalletCore, storage: Types.IStorage);
    hasWallet(id: string): Promise<boolean>;
    load(id: string): Promise<Types.Wallet>;
    loadAll(): Promise<Types.Wallet[]>;
    delete(id: string, password: string): Promise<void>;
    mapWallet(storedKey: StoredKey): Types.Wallet;
    mapStoredKey(wallet: Types.Wallet): StoredKey;
    importWallet(wallet: Types.Wallet): Promise<void>;
    import(mnemonic: string, name: string, password: string, coins: CoinType[], encryption: StoredKeyEncryption): Promise<Types.Wallet>;
    importKey(key: Uint8Array, name: string, password: string, coin: CoinType, encryption: StoredKeyEncryption): Promise<Types.Wallet>;
    addAccounts(id: string, password: string, coins: CoinType[]): Promise<Types.Wallet>;
    getKey(id: string, password: string, account: Types.ActiveAccount): Promise<PrivateKey>;
    export(id: string, password: string): Promise<string | Uint8Array>;
}
