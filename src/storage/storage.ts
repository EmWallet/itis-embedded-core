export class StorageWallet {
    private _storage: globalThis.Storage

    constructor () {
        this._storage = window.localStorage
    }

    public save (key: string, data: any): boolean {
        try {
            const value = typeof data === 'string' ? data : JSON.stringify(data);
            this._storage.setItem(`embedded-${key}`, value);
        } catch (error) {
            console.error("Failed to save data to storage:", error);
            return false
        }
        return true
    }

    public get(key: string): any | undefined {
        try {
            return this._storage.getItem(`embedded-${key}`);
        } catch (error) {
            console.error("Failed to retrieve data from storage:", error);
            return undefined;
        }
    }
    

    public del(key: string): boolean {
        try {
            this._storage.removeItem(`embedded-${key}`);
        } catch (error) {
            console.error("Failed to delete data from storage:", error);
            return false;
        }
        return true;
    }
}
