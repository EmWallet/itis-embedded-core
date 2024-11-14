import dayjs from 'dayjs';
import { Address, fromNano } from '@ton/ton';
import { formatUnits } from "ethers";
import {
  BaseTxnParsed,
  GetAccountEventsDTO,
  GetRatesDTO,
  GetTransferJettonHistoryDTO,
  TokenInfo,
  TxnDirection,
} from '../types';
import { JettonMetadataResponse } from '../types/getJettonDataByIdDTO';

export const jettonDataToTokenBalance = (
  token: JettonMetadataResponse,
  rates: GetRatesDTO
): TokenInfo => {
  const contract = Address.parse(token.metadata.address).toString({
    bounceable: true,
  });
  const metadata = token.metadata;
  const price = rates.rates[contract];
  return {
    tokenContract: contract,
    tokenID: metadata?.name,
    tokenSymbol: metadata?.symbol,
    tokenIcon: metadata?.image,
    tokenName: metadata?.name,
    change24h: parseFloat(
      price?.diff_24h.USD.replace('−', '-').replace('%', '')
    ),
    price: price.prices['USD'],
    isNativeToken: false,
  };
};

export const getAccountEventsDTOToParsedTxn = (
  dto: GetAccountEventsDTO,
  originAddress: string
): BaseTxnParsed[] => {
  return dto.events
    .filter(tx => tx.actions[0].type === 'TonTransfer')
    .map<BaseTxnParsed>(event => {
      const amount = parseFloat(
        fromNano(event.actions[0].TonTransfer?.amount ?? 0)
      );
      const sender = Address.parse(
        event.actions[0].TonTransfer?.sender?.address ?? ''
      ).toString({
        bounceable: false,
      });
      const recipient = Address.parse(
        event.actions[0].TonTransfer?.recipient?.address ?? ''
      ).toString({ bounceable: false });
      const direction: TxnDirection = originAddress === sender ? 'OUT' : 'IN';
      const timestamp = dayjs.unix(event.timestamp).toDate();

      return {
        actionType: event.actions[0].type,
        hash: event.event_id,
        amount: amount,
        status: event.actions[0].status === 'ok' ? 'applied' : 'failed',
        symbol: 'TON',
        timestamp,
        from: sender,
        to: recipient,
        direction,
      };
    });
};

export const getTransferJettonHistoryDTOToParsedTxn = (
    dto: GetTransferJettonHistoryDTO,
    originAddress: string
): BaseTxnParsed[] => {
    return dto.events.map<BaseTxnParsed>((event) => {
        const amount = parseFloat(
            formatUnits(
                event.actions[0].JettonTransfer?.amount ?? 0,
                event.actions[0].JettonTransfer?.jetton.decimals
            )
        );
        const sender = Address.parse(
            event.actions[0].JettonTransfer?.sender?.address ?? ""
        ).toString({ bounceable: false });
        const recipient = Address.parse(
            event.actions[0].JettonTransfer?.recipient?.address ?? ""
        ).toString({ bounceable: false });
        const direction: TxnDirection = originAddress === sender ? "OUT" : "IN";
        const timestamp = dayjs.unix(event.timestamp).toDate();

        return {
            actionType: event.actions[0].type,
            hash: event.event_id,
            amount: amount,
            status: event.actions[0].status === "ok" ? "applied" : "failed",
            symbol: event.actions[0].JettonTransfer?.jetton.symbol ?? "",
            timestamp,
            from: sender,
            to: recipient,
            direction,
        };
    });
};
