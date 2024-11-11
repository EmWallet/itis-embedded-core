import {
  mnemonicNew,
  mnemonicToPrivateKey,
  mnemonicValidate,
} from 'ton-crypto';
import WebAppSDK from '@twa-dev/sdk';
import { WalletContractV4 } from '@ton/ton';
import { StorageWallet } from '../storage';
import { TelegramStorage } from '../telegram-storage';
import { CryptoService } from '../crypto-service';

enum StorageKeys {
  SALT = 'salt',
  IV = 'iv',
  CIPHERTEXT = 'ciphertext',
  PUBLIC = 'public',
  ADDRESS = 'address',
}

const workchain = 0;

export class EmbeddedWallet {
  private _storage: StorageWallet | TelegramStorage;

  constructor() {
    this._storage =
      WebAppSDK.initData.length !== 0 && !(WebAppSDK.platform === 'macos')
        ? new TelegramStorage()
        : new StorageWallet();
  }

  public async createNewWallet(password: string): Promise<boolean> {
    // Generate new mnemonic
    const mnemonics = await mnemonicNew();
    const keyPair = await mnemonicToPrivateKey(mnemonics);

    // Create wallet contract
    const wallet = WalletContractV4.create({
      workchain,
      publicKey: keyPair.publicKey,
    });

    return (
      (await this.saveMnemonic(mnemonics.join(' '), password)) &&
      this._storage.save(StorageKeys.PUBLIC, wallet.publicKey) &&
      this._storage.save(StorageKeys.ADDRESS, wallet.address)
    );
  }

  public async createWalletFromMnemonic(
    password: string,
    mnemonics: string[]
  ): Promise<boolean> {
    if (!mnemonicValidate(mnemonics)) {
      console.error('Invalid mnemonic');
      return false;
    }
    const keyPair = await mnemonicToPrivateKey(mnemonics);

    // Create wallet contract
    const wallet = WalletContractV4.create({
      workchain,
      publicKey: keyPair.publicKey,
    });

    return (
      (await this.saveMnemonic(mnemonics.join(' '), password)) &&
      this._storage.save(StorageKeys.PUBLIC, wallet.publicKey) &&
      this._storage.save(StorageKeys.ADDRESS, wallet.address)
    );
  }

  private async saveMnemonic(
    mnemonic: string,
    password: string
  ): Promise<boolean> {
    try {
      const encryptedData = await CryptoService.encrypt(password, mnemonic);

      return (
        this._storage.save(StorageKeys.SALT, encryptedData.salt) &&
        this._storage.save(StorageKeys.IV, encryptedData.iv) &&
        this._storage.save(StorageKeys.CIPHERTEXT, encryptedData.ciphertext)
      );
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  public async loadMnemonic(password: string): Promise<string | null> {
    const salt = this._storage.get(StorageKeys.SALT);
    const iv = this._storage.get(StorageKeys.IV);
    const ciphertext = this._storage.get(StorageKeys.CIPHERTEXT);

    if (salt && iv && ciphertext) {
      try {
        const mnemonic = await CryptoService.decrypt(password, {
          salt,
          iv,
          ciphertext,
        });
        return mnemonic;
      } catch (error) {
        console.error(error);
        return null;
      }
    }
    return null;
  }

  public async getPrivateKeyHex(password: string): Promise<string> {
    const mnemonic = await this.loadMnemonic(password);

    if (!mnemonic) {
      throw new Error('Invalid password');
    }

    const keyPair = await mnemonicToPrivateKey(mnemonic.split(' '));
    return keyPair.secretKey.toString('hex');
  }

  public async exitWallet(): Promise<boolean> {
    try {
      const keys = [
        StorageKeys.IV,
        StorageKeys.SALT,
        StorageKeys.CIPHERTEXT,
        StorageKeys.ADDRESS,
        StorageKeys.PUBLIC,
      ];
      keys.forEach(key => this._storage.del(key));
      return true;
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  public isAuth(): boolean {
    const hash = this._storage.get(StorageKeys.CIPHERTEXT);
    const iv = this._storage.get(StorageKeys.IV);
    const salt = this._storage.get(StorageKeys.SALT);
    const publicKey = this._storage.get(StorageKeys.PUBLIC);
    const address = this._storage.get(StorageKeys.ADDRESS);

    return Boolean(iv && hash && salt && publicKey && address);
  }
}
