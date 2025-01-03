import axios from 'axios';
import {
  BaseTxnParsed,
  GetAccountEventsDTO,
  GetAccountTransactionDTO,
  GetAddressByDomainDTO,
  GetAllJettonsBalancesDTO,
  GetAllNFTsDTO,
  GetRatesDTO,
  GetTokenChartDTO,
  GetTransferJettonHistoryDTO,
  GetWalletInfoDTO,
  TokenInfo,
} from '../types';
import {
  GetJettonDataByIdDTO,
  JettonMetadataResponse,
} from '../types/getJettonDataByIdDTO';
import {
  getAccountEventsDTOToParsedTxn,
  getTransferJettonHistoryDTOToParsedTxn,
  jettonDataToTokenBalance,
} from '../utils';
import { GetNFT_DTO } from '../types/getNFTDTO';

interface TonAPIClientOptions {
  url?: string;
  token?: string;
}

type HTTPResponse<T> = {
  data: T;
};

type GetOptions = {
  params?: Record<string, any>;
  headers?: Record<string, string>;
};

type Lang = 'en' | 'ru';

interface HTTPClient {
  get<T>(url: string, options?: GetOptions): Promise<HTTPResponse<T>>;
}

export class TonAPIClient {
  private httpClient: HTTPClient;

  constructor({
    url = 'https://tonapi.io/v2/',
    token,
  }: TonAPIClientOptions = {}) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};

    this.httpClient = axios.create({
      baseURL: url,
      headers,
    });
  }

  private parseResponse<T>(res: HTTPResponse<T>) {
    return res.data;
  }

  private get<T>(url: string, options?: GetOptions) {
    return this.httpClient.get<T>(url, options).then(this.parseResponse);
  }

  // account
  public getWalletInfo({ account }: { account: string }) {
    return this.get<GetWalletInfoDTO>(`/accounts/${account}`);
  }

  public getAccountTransactions({
    account,
    limit = 100,
  }: {
    account: string;
    limit?: number;
  }) {
    return this.get<GetAccountTransactionDTO>(
      `/blockchain/accounts/${account}/transactions`,
      {
        params: new URLSearchParams({
          limit: limit.toString(),
        }),
      }
    );
  }

  public getAccountEvents({
    account,
    language = 'en',
    limit = 20,
  }: {
    account: string;
    language?: Lang;
    limit?: number;
  }) {
    const options: GetOptions = {
      headers: {
        'Accept-Language': language,
      },
      params: new URLSearchParams({
        limit: limit.toString(),
      }),
    };
    return this.get<GetAccountEventsDTO>(
      `/accounts/${account}/events`,
      options
    );
  }

  //   for ton parsed history
  public async getParsedTonTransfersHistory({
    address,
    deep = 100,
  }: {
    address: string;
    deep?: number;
  }): Promise<BaseTxnParsed[]> {
    const tonTxs = await this.getAccountEvents({
      account: address,
      limit: deep,
    });
    return getAccountEventsDTOToParsedTxn(tonTxs, address);
  }

  //   for parsed jetton history
  public async getParsedJettonTransfersHistory({
    address,
    jettonAddress,
    deep = 500,
  }: {
    address: string;
    jettonAddress: string;
    deep?: number;
  }): Promise<BaseTxnParsed[]> {
    const jettonTxs = await this.getTransferJettonHistory({
      account: address,
      jettonId: jettonAddress,
      limit: deep,
    });
    return getTransferJettonHistoryDTOToParsedTxn(jettonTxs, address);
  }

  // tokens

  public getRates({
    tokens,
    currencies = ['usd'],
  }: {
    tokens: string[];
    currencies?: string[];
  }) {
    return this.get<GetRatesDTO>('/rates', {
      params: new URLSearchParams({
        tokens: tokens.join(','),
        currencies: currencies.join(','),
      }),
    });
  }

  public async getJettonDataById({
    jettonAddress,
  }: GetJettonDataByIdDTO): Promise<TokenInfo> {
    const metadata = await this.get<JettonMetadataResponse>(
      `/jettons/${jettonAddress}`
    );
    const rates = await this.getRates({ tokens: [jettonAddress] });
    // console.log(rates);
    return jettonDataToTokenBalance(metadata, rates);
  }

  public getTransferJettonHistory({
    account,
    language = 'en',
    limit = 20,
    jettonId,
    startDate,
    endDate,
    beforeIt,
  }: {
    account: string;
    jettonId: string;
    language?: Lang;
    limit?: number;
    beforeIt?: bigint;
    startDate?: bigint;
    endDate?: bigint;
  }) {
    const params = new URLSearchParams({
      limit: limit.toString(),
    });
    beforeIt && params.set('before-it', beforeIt.toString());
    startDate && params.set('start-date', startDate.toString());
    endDate && params.set('end-date', endDate.toString());

    const options: GetOptions = {
      headers: {
        'Accept-Language': language,
      },
      params,
    };
    return this.get<GetTransferJettonHistoryDTO>(
      `/accounts/${account}/jettons/${jettonId}/history`,
      options
    );
  }

  public getAllJettonsBalances({
    account,
    currencies,
  }: {
    account: string;
    currencies?: string[];
  }) {
    const params = new URLSearchParams();
    currencies && params.set('currencies', currencies.join(','));
    return this.get<GetAllJettonsBalancesDTO>(`/accounts/${account}/jettons`, {
      params,
    });
  }

  public getTokenChart({
    tokenAddress,
    currency,
  }: {
    tokenAddress: string;
    currency: string;
    startDate?: number;
    endDate?: number;
  }) {
    const params = new URLSearchParams({
      token: tokenAddress,
    });
    params.set('currency', currency);

    return this.get<GetTokenChartDTO>('/rates/chart', {
      params,
    });
  }

  // dns
  public async getAddressByDomain({ domain }: { domain: string }) {
    return this.get<GetAddressByDomainDTO>(`/dns/${domain}/resolve`);
  }

  // nft
  public getAllNFTs({
    account,
    collection,
    limit,
    offset,
    indirectOwnership,
  }: {
    account: string;
    collection?: string;
    limit?: number;
    offset?: number;
    indirectOwnership?: boolean;
  }) {
    const params = new URLSearchParams();
    collection && params.set('collection', collection);
    limit && params.set('limit', limit.toString());
    offset && params.set('offset', offset.toString());
    indirectOwnership && params.set('indirect_ownership', 'true');

    return this.get<GetAllNFTsDTO>(`accounts/${account}/nfts`, {
      params,
    });
  }

  public getNFTDetails({ address }: { address: string }) {
    return this.get<GetNFT_DTO>(`nfts/${address}`);
  }
}
