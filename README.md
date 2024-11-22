# itis-embedded-core

`itis-embedded-core` is a library designed for seamless integration of TON wallet functionality into your frontend application. The library provides a comprehensive set of methods, covering the functionality of an embedded TON wallet. With this library, you can create a wallet, retrieve wallet data, and send transactions.

The library addresses the challenge of securely storing your wallet's private key on the client side. It utilizes the Web Crypto API to safely encrypt and decrypt your private key.

## Features

- Create a new TON wallet or import an existing one via mnemonic.
- Safely store and encrypt wallet data on the client side.
- Retrieve wallet details such as address and balance.
- Send TON and Jettons transactions with support for comments.
- Fetch transaction history for TON and Jetton transfers.
- Validate blockchain addresses.
- Retrieve real-time token rates and balances for Jettons.
- Access NFT collections and DNS data for TON accounts.

## Installation

Install the library via npm:

```bash
npm install @emwallet/itis-embedded-core
yarn add @emwallet/itis-embedded-core
```

## usage example

```typescript
import {
  EmbeddedWallet,
  TonAPIClient,
} from '@emwallet/itis-embedded-core';

// Initialize the wallet and TonAPI client
const wallet = new EmbeddedWallet();
const tonAPIClient = new TonAPIClient({ token: 'YOUR_TONAPI_TOKEN' });

async function main() {
  // Attempt to create a new wallet
  console.log('Creating a new wallet...');
  try {
    await wallet.createNewWallet('secure-password');
    console.log('Wallet successfully created.');
  } catch (error) {
    console.error(error);
    if (error.message === 'Wallet already exists.') {
      console.log(
        'Wallet already exists. Continuing with the existing wallet.'
      );
    } else {
      // Handle other errors accordingly
      return;
    }
  }

  // Check if the wallet is authenticated
  try {
    const isAuthenticated = await wallet.isAuth();
    console.log('Is wallet authenticated:', isAuthenticated);
  } catch (error) {
    console.error(error);
    return;
  }

  // Verify if the password is correct
  try {
    const isPasswordCorrect = await wallet.verifyPassword('secure-password');
    console.log('Is password correct:', isPasswordCorrect);
  } catch (error) {
    console.error(error);
  }

  // Get the mnemonic with the correct password
  try {
    const mnemonic = await wallet.getMnemonic('secure-password');
    console.log('Wallet mnemonic:', mnemonic);
  } catch (error) {
    console.error(error);
  }

  // Attempt to get the mnemonic with an incorrect password
  try {
    const mnemonic = await wallet.getMnemonic('wrong-password');
    console.log('Wallet mnemonic:', mnemonic);
  } catch (error) {
    console.error(error);
  }

  // Get the private key
  try {
    const privateKeyHex = await wallet.getPrivateKeyHex('secure-password');
    console.log('Private key (Hex):', privateKeyHex);
  } catch (error) {
    console.error(error);
  }

  let address: string;
  try {
    // Retrieve the wallet address
    address = await wallet.getAddress();
    console.log('Wallet address:', address);
  } catch (error) {
    console.error(error);
    return;
  }

  // Validate the wallet address
  try {
    const validAddress = EmbeddedWallet.isValidAddress(address);
    console.log('Is valid address:', validAddress);
  } catch (error) {
    console.error(error);
  }

  // Get the wallet balance
  try {
    const balance = await wallet.getTonBalance();
    console.log('Wallet balance:', balance, 'TON');
  } catch (error) {
    console.error(error);
  }

  // Send a TON transaction
  try {
    console.log('Sending a transaction...');
    await wallet.transferTon({
      password: 'secure-password',
      amount: '1000000000', // 1 TON in nanocoins
      receiver: 'EQDc...recipientAddress...', // Replace with a valid recipient address
      comment: 'Payment for services',
    });
    console.log('TON successfully sent.');
  } catch (error) {
    console.error(error);
  }

  // Send Jettons
  try {
    console.log('Sending Jettons...');
    await wallet.transferJetton({
      password: 'secure-password',
      amount: '500000000', // Amount of Jettons in nano tokens
      receiver: 'EQDc...recipientAddress...', // Replace with a valid recipient address
      jettonAddress: 'EQDc...jettonMasterAddress...', // Jetton Master contract address
      comment: 'Jetton payment',
    });
    console.log('Jettons successfully sent.');
  } catch (error) {
    console.error(error);
  }

  // Fetch transaction history (TON transfers)
  try {
    console.log('Fetching TON transaction history...');
    const tonHistory = await tonAPIClient.getParsedTonTransfersHistory({
      address,
    });
    console.log('TON Transaction History:', tonHistory);
  } catch (error) {
    console.error(error);
  }

  // Fetch transaction history (Jetton transfers)
  try {
    console.log('Fetching Jetton transaction history...');
    const jettonHistory = await tonAPIClient.getParsedJettonTransfersHistory({
      address,
      jettonAddress: 'EQDc...jettonAddress...', // Replace with a valid Jetton address
    });
    console.log('Jetton Transaction History:', jettonHistory);
  } catch (error) {
    console.error(error);
  }

  // Exit the wallet
  try {
    console.log('Exiting the wallet...');
    await wallet.exitWallet();
    console.log('Wallet data successfully cleared.');
  } catch (error) {
    console.error(error);
  }
}

main();
```

# Error Handling

In the example above, each operation is wrapped in its own try-catch block. This allows you to handle errors specific to each operation and continue executing subsequent operations without interruption.

## Examples of Possible Errors and Their Handling:

Creating a Wallet When One Already Exists: If you attempt to create a new wallet when one already exists, the createNewWallet method will throw an error with the message 'Wallet already exists.'. In the example, this error is caught, and appropriate action is taken.

Retrieving the Mnemonic with Incorrect Password: If you enter an incorrect password when trying to retrieve the mnemonic, the getMnemonic method will throw an error with the message 'Failed to decrypt mnemonic. Possibly incorrect password.'. In the example, this error is caught and logged.

Checking Authentication: If an error occurs while checking the wallet's authentication status, such as issues with storage, the error will be caught, and the program execution can be halted using return.

Sending a Transaction: If an error occurs while sending a transaction (e.g., due to an invalid recipient address or TON client issues), it will be caught and logged to the console.

# Address Validation

You can use the static method isValidAddress to check the validity of a TON address:

```typescript
try {
  const validAddress = EmbeddedWallet.isValidAddress(address);
  console.log('Is valid address:', validAddress);
} catch (error) {
  console.error(error);
}
```

# Important Notes
## Using with Vite
When developing with Vite, you need to include a polyfill for Buffer, as it may not be available in the browser environment by default. This is necessary because the library uses the Node.js Buffer API, which Vite does not automatically polyfill.

## Local Development with Telegram Mini Apps (TMA)
When developing locally for Telegram Mini Apps (TMA), it's recommended to use NGROK or a similar tool to expose your local server over HTTPS. This is necessary because the Web Crypto API, which the library uses for secure encryption and decryption, requires a secure context (HTTPS).
