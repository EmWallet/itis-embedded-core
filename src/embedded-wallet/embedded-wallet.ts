import {
  mnemonicNew,
  mnemonicToPrivateKey,
  mnemonicValidate,
} from 'ton-crypto';
import WebAppSDK from '@twa-dev/sdk';
import {
  Address,
  Cell,
  comment,
  fromNano,
  internal,
  TonClient4,
  WalletContractV4,
} from '@ton/ton';
import { StorageWallet } from '../storage';
import { TelegramStorage } from '../telegram-storage';
import { CryptoService } from '../crypto-service';
import {
  ISendTonTransaction,
  ITransferTonOptions,
  StorageKeys,
} from '../types';

const defaultTonClient4Endpoint = 'https://mainnet-v4.tonhubapi.com';
// const defaultTonClientEndpoint = 'https://toncenter.com/api/v2/jsonRPC';

const workchain = 0;

interface EmbeddedWalletOptions {
  tonClient4Endpoint?: string;
  tonClientEndpoint?: string;
  tonClientApiKey?: string;
}

export class EmbeddedWallet {
  private _storage: StorageWallet | TelegramStorage;
  private _tonClient4: TonClient4;
  // private _tonClient: TonClient;

  constructor(options?: EmbeddedWalletOptions) {
    this._storage =
      (WebAppSDK as any)?.initData?.length !== 0
        ? new TelegramStorage()
        : new StorageWallet();

    const tonClient4Endpoint =
      options?.tonClient4Endpoint || defaultTonClient4Endpoint;
    this._tonClient4 = new TonClient4({ endpoint: tonClient4Endpoint });

    // const tonClientEndpoint =
    //   options?.tonClientEndpoint || defaultTonClientEndpoint;
    // const tonClientApiKey = options?.tonClientApiKey;
    // this._tonClient = new TonClient({
    //   endpoint: tonClientEndpoint,
    //   apiKey: tonClientApiKey,
    // });
  }

  private async initializeWalletData(
    mnemonic: string,
    password: string,
    publicKey: string,
    address: string
  ): Promise<void> {
    const mnemonicSaved = await this.saveMnemonic(mnemonic, password);
    const publicKeySaved = this._storage.save(StorageKeys.PUBLIC, publicKey);
    const addressSaved = this._storage.save(StorageKeys.ADDRESS, address);

    if (!mnemonicSaved || !publicKeySaved || !addressSaved) {
      throw new Error('Failed to initialize wallet data.');
    }
  }

  public async createNewWallet(password: string): Promise<void> {
    if (this.isAuth()) {
      throw new Error('Wallet already exists.');
    }

    const mnemonics = await mnemonicNew();
    const keyPair = await mnemonicToPrivateKey(mnemonics);
    const wallet = WalletContractV4.create({
      workchain,
      publicKey: keyPair.publicKey,
    });

    const userFriendlyAddress = wallet.address.toString({ bounceable: false });
    const userFriendlyPublic = wallet.publicKey.toString('hex');

    await this.initializeWalletData(
      mnemonics.join(' '),
      password,
      userFriendlyPublic,
      userFriendlyAddress
    );
  }

  public async createWalletFromMnemonic(
    password: string,
    mnemonics: string[]
  ): Promise<void> {
    if (this.isAuth()) {
      throw new Error('Wallet already exists.');
    }

    if (!mnemonicValidate(mnemonics)) {
      throw new Error('Invalid mnemonic.');
    }
    const keyPair = await mnemonicToPrivateKey(mnemonics);

    // Create wallet contract
    const wallet = WalletContractV4.create({
      workchain,
      publicKey: keyPair.publicKey,
    });

    const userFriendlyAddress = wallet.address.toString({ bounceable: false });
    const userFriendlyPublic = wallet.publicKey.toString('hex');

    await this.initializeWalletData(
      mnemonics.join(' '),
      password,
      userFriendlyPublic,
      userFriendlyAddress
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

  public async getMnemonic(password: string): Promise<string> {
    const salt = this._storage.get(StorageKeys.SALT);
    const iv = this._storage.get(StorageKeys.IV);
    const ciphertext = this._storage.get(StorageKeys.CIPHERTEXT);

    if (!salt || !iv || !ciphertext) {
      throw new Error('Mnemonic not found in storage.');
    }

    try {
      const mnemonic = await CryptoService.decrypt(password, {
        salt,
        iv,
        ciphertext,
      });
      return mnemonic;
    } catch (error) {
      throw new Error(
        'Failed to decrypt mnemonic. Possibly incorrect password.'
      );
    }
  }

  public async getPrivateKeyHex(password: string): Promise<string> {
    try {
      const mnemonic = await this.getMnemonic(password);

      if (!mnemonic) {
        throw new Error('Mnemonic not available.');
      }

      const keyPair = await mnemonicToPrivateKey(mnemonic.split(' '));
      return keyPair.secretKey.toString('hex');
    } catch (error) {
      throw new Error(
        `Failed to retrieve private key: ${this.formatErrorMessage(error)}`
      );
    }
  }

  public async exitWallet(): Promise<void> {
    try {
      const keys = [
        StorageKeys.IV,
        StorageKeys.SALT,
        StorageKeys.CIPHERTEXT,
        StorageKeys.ADDRESS,
        StorageKeys.PUBLIC,
      ];
      keys.forEach(key => this._storage.del(key));
    } catch (error) {
      throw new Error(
        `Failed to clear wallet data: ${this.formatErrorMessage(error)}`
      );
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

  public getAddress(): string {
    if (!this.isAuth()) {
      throw new Error('Wallet is not authenticated');
    }

    const address = this._storage.get(StorageKeys.ADDRESS);
    if (!address) {
      throw new Error('Address not found in storage');
    }

    return address;
  }

  public async getTonBalance(): Promise<string> {
    if (!this.isAuth()) {
      throw new Error('Wallet is not authenticated');
    }

    const publicKeyHex = this._storage.get(StorageKeys.PUBLIC);
    if (!publicKeyHex) {
      throw new Error('Public key not found in storage');
    }

    try {
      const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
      const wallet = WalletContractV4.create({
        workchain,
        publicKey: publicKeyBuffer,
      });

      const contract = this._tonClient4.open(wallet);
      const balance = await contract.getBalance();

      return fromNano(balance);
    } catch (error) {
      throw new Error(
        `Error fetching TON balance: ${this.formatErrorMessage(error)}`
      );
    }
  }

  private async sendTonTransaction(txData: ISendTonTransaction): Promise<void> {
    try {
      if (!this.isAuth()) {
        throw new Error('Wallet is not authenticated.');
      }

      const recipientAddress = Address.parse(txData.receiver);
      if (!Address.isAddress(recipientAddress)) {
        throw new Error('Invalid receiver address.');
      }

      const wallet = WalletContractV4.create({
        workchain,
        publicKey: txData.publicKey,
      });
      const contract = this._tonClient4.open(wallet);

      const seqno: number = await contract.getSeqno();

      let comm;
      if (txData.comment) comm = comment(txData.comment);
      const body = txData.data ? Cell.fromBase64(txData.data) : undefined;

      const msgs = [
        internal({
          value: BigInt(txData.amount),
          to: recipientAddress,
          bounce: false,
          body: body ?? comm,
        }),
      ];

      const transfer = contract.createTransfer({
        seqno,
        secretKey: txData.secretKey,
        sendMode: 1 + 2,
        messages: msgs,
      });
      await contract.send(transfer);
    } catch (error) {
      console.error('Error in sendTonTransaction:', error);
      throw new Error(
        `Failed to send transaction: ${this.formatErrorMessage(error)}`
      );
    }
  }

  public async transferTon(options: ITransferTonOptions): Promise<void> {
    const mnemonic = await this.getMnemonic(options.password);
    const keyPair = await mnemonicToPrivateKey(mnemonic.split(' '));

    const txData: ISendTonTransaction = {
      amount: options.amount,
      receiver: options.receiver,
      comment: options.comment,
      secretKey: keyPair.secretKey,
      publicKey: keyPair.publicKey,
    };

    await this.sendTonTransaction(txData);
  }

  private formatErrorMessage(error: unknown): string {
    return error instanceof Error ? error.message : 'Unknown error';
  }

  public static isValidAddress(address: string): boolean {
    try {
      return Address.isAddress(Address.parse(address));
    } catch (error) {
      return false;
    }
  }
}
