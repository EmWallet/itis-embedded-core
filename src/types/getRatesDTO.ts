interface TokenRates {
    prices: { [key: string]: number };
    diff_24h: { [key: string]: string };
    diff_7d: { [key: string]: string };
    diff_30d: { [key: string]: string };
}

export interface GetRatesDTO {
    rates: {
        [key: string]: TokenRates;
    };
}
