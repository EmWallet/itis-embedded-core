export * from "./getRatesDTO";
export * from "./getAccountEventsDTO";
export * from "./getAccountTransactionsDTO";
export * from "./getAllJettonBalancesDTO";
export * from "./getWalletInfoDTO";
export * from "./getTransferJettonHistoryDTO";
export * from "./getTokenChartDTO";
export * from "./getAddressByDomainDTO";
export * from "./getAllNFTsDTO";

export interface ISendTonTransaction {
  amount: string;
  receiver: string;
  comment?: string;
  data?: string;
  secretKey: Buffer;
  publicKey: Buffer;
}

export interface ITransferTonOptions {
    password: string;
    receiver: string;
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

export interface BaseToken {
  tokenContract?: string;
  tokenID: string;
  tokenSymbol: string;
  tokenName: string;
  tokenIcon?: string;
  decimals?: number;
  isNativeToken: boolean;
  price?: number;
}

export interface TokenInfo extends BaseToken {
  balance?: number;
  balanceUSD?: number;
  price: number;
  change24h?: number;
}

export type TxnStatus = "applied" | "failed";
export type TxnDirection = "IN" | "OUT";

export type TransactionResponseNormal<T> = {
    isError: boolean;
    transaction: T | null;
    errorMessage?: string;
};

export type TransactionResponseFail = {
    isError: true;
    transaction: null;
    errorMessage: string;
};

export type TransactionResponse<T> = TransactionResponseNormal<T> | TransactionResponseFail;

export interface BaseTxnParsed {
    actionType: string;
    hash: string;
    amount: number;
    status: TxnStatus;
    symbol: string;
    timestamp?: Date;
    from: string;
    to: string;
    direction: TxnDirection;
    fee?: number;
}
