import {
  mnemonicNew,
  mnemonicToPrivateKey,
  mnemonicValidate,
} from 'ton-crypto';
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
  TransferOptions,
  TransToSignJetton,
} from '../types';
import { TokenWallet } from '../token-wallet/token-wallet';

const defaultTonClient4Endpoint = 'https://mainnet-v4.tonhubapi.com';
// const defaultTonClientEndpoint = 'https://toncenter.com/api/v2/jsonRPC';

const workchain = 0;

interface EmbeddedWalletOptions {
  tonClient4Endpoint?: string;
  tonClientEndpoint?: string;
  tonClientApiKey?: string;
}

declare global {
  interface Window {
    Telegram?: any;
  }
}

export class EmbeddedWallet {
  private _storage: StorageWallet | TelegramStorage;
  private _tonClient4: TonClient4;
  // private _tonClient: TonClient;

  constructor(options?: EmbeddedWalletOptions) {
    const isTelegramEnvironment =
    typeof window.Telegram !== 'undefined' &&
    window.Telegram.WebApp &&
    window.Telegram.WebApp.initData &&
    window.Telegram.WebApp.initData.length !== 0;
    this._storage = isTelegramEnvironment ? new TelegramStorage() : new StorageWallet();

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
    if (await this.isAuth()) {
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
    if (await this.isAuth()) {
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

  public async verifyPassword(password: string): Promise<boolean> {
    try {
      const mnemonic = await this.getMnemonic(password);
      const isValid = await mnemonicValidate(mnemonic.split(' '));
      return isValid;
    } catch (error) {
      return false;
    }
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
    const salt = await this._storage.get(StorageKeys.SALT);
    const iv = await this._storage.get(StorageKeys.IV);
    const ciphertext = await this._storage.get(StorageKeys.CIPHERTEXT);

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

  public async isAuth(): Promise<boolean> {
    try {
      const [hash, iv, salt, publicKey, address] = await Promise.all([
        this._storage.get(StorageKeys.CIPHERTEXT),
        this._storage.get(StorageKeys.IV),
        this._storage.get(StorageKeys.SALT),
        this._storage.get(StorageKeys.PUBLIC),
        this._storage.get(StorageKeys.ADDRESS),
      ]);

      return Boolean(iv && hash && salt && publicKey && address);
    } catch (error) {
      console.error('Error checking authentication:', error);
      return false;
    }
  }

  public async getAddress(): Promise<string> {
    if (!(await this.isAuth())) {
      throw new Error('Wallet is not authenticated');
    }

    const address = await this._storage.get(StorageKeys.ADDRESS);
    if (!address) {
      throw new Error('Address not found in storage');
    }

    return address;
  }

  public async getTonBalance(): Promise<string> {
    if (!this.isAuth()) {
      throw new Error('Wallet is not authenticated');
    }

    const publicKeyHex = await this._storage.get(StorageKeys.PUBLIC);
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

  //   public async transferJetton (options: ITransferJettonOptions): Promise<void> {

  //     const dataJ = EmbeddedWallet.sendJettonToBoc(trJ, )

  //     const jettonWallet = await this.resolveJettonAddressFor(Address.parse(tokenAddress), Address.parse(loadData.address))

  //     if (!jettonWallet) {
  //       throw new Error('Resolve JettonWallet error');

  //     }
  // }

  public static sendJettonToBoc(
    tr: TransToSignJetton,
    addressUser: string
  ): string {
    const transJetton: TransferOptions = {
      queryId: 1,
      tokenAmount: BigInt(tr.amount),
      to: Address.parse(tr.to.toString()), // to address
      responseAddress: Address.parse(addressUser.toString()),
      comment: tr.comment,
    };

    const boc = TokenWallet.buildTransferMessage(transJetton);

    const base64 = boc.toBoc().toString('base64');
    return base64;
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
