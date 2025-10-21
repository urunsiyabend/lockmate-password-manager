// src/hooks/useVaultKey.ts
import { useCallback, useEffect, useState } from "react";

const STORAGE_KEY = "LOCKMATE_VAULT_KEY";

export function useVaultKey() {
    const [vaultKey, setVaultKeyState] = useState<string | undefined>(() =>
        localStorage.getItem(STORAGE_KEY) || undefined
    );

    useEffect(() => {
        const stored = localStorage.getItem(STORAGE_KEY) || undefined;
        if (stored !== vaultKey) setVaultKeyState(stored);
    }, []); // once on mount

    const setVaultKey = useCallback((key?: string) => {
        if (key && key.trim()) {
            localStorage.setItem(STORAGE_KEY, key);
            setVaultKeyState(key);
        } else {
            localStorage.removeItem(STORAGE_KEY);
            setVaultKeyState(undefined);
        }
    }, []);

    return { vaultKey, setVaultKey };
}
