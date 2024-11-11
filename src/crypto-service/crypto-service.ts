export class CryptoService {
    private static iteration = 100000;
    private static encryptionAlgorithm = "AES-GCM";
    private static ivLength = 12;
    private static saltLength = 16;
    private static digest = "SHA-256";
    private static enc = new TextEncoder();
    private static dec = new TextDecoder();
  
    private static base64Encode(u8: Uint8Array): string {
      return btoa(String.fromCharCode(...u8));
    }
  
    private static base64Decode(str: string): Uint8Array {
      return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
    }
  
    private static async getPasswordKey(secretKey: string): Promise<CryptoKey> {
      return window.crypto.subtle.importKey(
        "raw",
        CryptoService.enc.encode(secretKey),
        "PBKDF2",
        false,
        ["deriveKey"]
      );
    }
  
    private static async deriveKey(
      passwordKey: CryptoKey,
      salt: Uint8Array,
      iteration: number,
      digest: string,
      encryptionAlgorithm: string,
      keyUsage: KeyUsage[]
    ): Promise<CryptoKey> {
      return window.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: iteration,
          hash: digest,
        },
        passwordKey,
        {
          name: encryptionAlgorithm,
          length: 256,
        },
        false,
        keyUsage
      );
    }
  
    public static async encrypt(
      secretKey: string,
      data: string
    ): Promise<{ salt: string; iv: string; ciphertext: string }> {
      try {
        const salt = window.crypto.getRandomValues(
          new Uint8Array(CryptoService.saltLength)
        );
        const iv = window.crypto.getRandomValues(
          new Uint8Array(CryptoService.ivLength)
        );
        const passwordKey = await CryptoService.getPasswordKey(secretKey);
        const aesKey = await CryptoService.deriveKey(
          passwordKey,
          salt,
          CryptoService.iteration,
          CryptoService.digest,
          CryptoService.encryptionAlgorithm,
          ["encrypt"]
        );
        const encryptedContent = await window.crypto.subtle.encrypt(
          {
            name: CryptoService.encryptionAlgorithm,
            iv,
          },
          aesKey,
          CryptoService.enc.encode(data)
        );
        const encryptedContentArr = new Uint8Array(encryptedContent);

        const encodedSalt = CryptoService.base64Encode(salt);
        const encodedIv = CryptoService.base64Encode(iv);
        const encodedCiphertext = CryptoService.base64Encode(encryptedContentArr);
  
        return {
          salt: encodedSalt,
          iv: encodedIv,
          ciphertext: encodedCiphertext,
        };
      } catch (error) {
        throw new Error(`Encryption failed: ${(error as Error).message}`);
      }
    }
  
    public static async decrypt(
      secretKey: string,
      encryptedData: { salt: string; iv: string; ciphertext: string }
    ): Promise<string> {
      try {
        const salt = CryptoService.base64Decode(encryptedData.salt);
        const iv = CryptoService.base64Decode(encryptedData.iv);
        const data = CryptoService.base64Decode(encryptedData.ciphertext);
  
        const passwordKey = await CryptoService.getPasswordKey(secretKey);
        const aesKey = await CryptoService.deriveKey(
          passwordKey,
          salt,
          CryptoService.iteration,
          CryptoService.digest,
          CryptoService.encryptionAlgorithm,
          ["decrypt"]
        );
        const decryptedContent = await window.crypto.subtle.decrypt(
          {
            name: CryptoService.encryptionAlgorithm,
            iv,
          },
          aesKey,
          data
        );
        return CryptoService.dec.decode(decryptedContent);
      } catch (error) {
        throw new Error(`Decryption failed: ${(error as Error).message}`);
      }
    }
  }
  