import { Builder, Cell, toNano } from '@ton/ton';
import { TransferOptions } from '../types';
const WALLET_OP = {
  burn_query: 0x3a3b4252,
  transfer_query: 0xf8a7ea5,
  bouncable_transfer_query: 0x3a81b46,
};

class TokenWallet {
  private static newQueryId(): number {
    return ~~(Date.now() / 1000);
  }

  public static buildTransferMessage(options: TransferOptions): Cell {
    const {
      queryId = this.newQueryId(),
      tokenAmount,
      to,
      responseAddress,
      fwdAmount = toNano(0.01),
    } = options;

    const op = WALLET_OP.transfer_query;

    // transfer_query or bouncable_transfer_query
    const body = new Builder()
      .storeUint(op, 32) // op
      .storeUint(queryId, 64) // query_id
      .storeCoins(tokenAmount) // token_amount
      .storeAddress(to) // to_address
      .storeAddress(responseAddress) // response_address
      .storeBit(0) // custom_payload:(Maybe ^Cell)
      .storeCoins(fwdAmount); // fwd_amount

    const fwdBody = options.comment
      ? new Builder()
          .storeUint(0, 32)
          .storeStringRefTail(options.comment ?? '')
          .endCell()
      : new Builder().endCell();

    if (body.bits + fwdBody.bits.length > 1023) {
      body.storeBit(1).storeRef(fwdBody);
    } else {
      body.storeBit(0).storeSlice(fwdBody.asSlice());
    }

    return body.asCell();
  }
}

export { TokenWallet };
