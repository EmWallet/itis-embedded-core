import { CloudStorage } from "@twa-dev/types";

declare global {
    interface Window {
      Telegram?: any;
    }
  }

export class TelegramStorage {
    private _storage: CloudStorage

    constructor () {
        this._storage = window?.Telegram?.WebApp?.CloudStorage
    }

    public save (key: string, data: any | string): boolean {
        try {
            this._storage?.setItem(`embedded-${key}`, data)
            return true
        } catch (error) {
            console.error(error)
            return false
        }
    }

    public get (key: string): Promise<any | undefined> {
        return new Promise((resolve, reject) => {
            try {
                this._storage?.getItem(`embedded-${key}`, (error: any, result: any) => {
                    if (error || result === null || result === undefined) {
                        reject(error || 'Result is null or undefined')
                    } else {
                        resolve(result)
                    }
                })
            } catch (error) {
                console.error(error)
                reject(error)
            }
        })
    }

    public del (key: string): boolean {
        try {
            this._storage?.removeItem(`embedded-${key}`)
            return true
        } catch (error) {
            console.error(error)
            return false
        }
    }
}
