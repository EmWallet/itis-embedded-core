export interface ISendTonTransaction {
  amount: string;
  to: string;
  comment?: string;
  data?: string;
  secretKey: Buffer;
  publicKey: Buffer;
}

export interface ITransferTonOptions {
    password: string;
    to: string;
    amount: string;
    comment?: string;
  }

export enum StorageKeys {
  SALT = 'salt',
  IV = 'iv',
  CIPHERTEXT = 'ciphertext',
  PUBLIC = 'public',
  ADDRESS = 'address',
}
