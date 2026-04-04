import { createContext, useCallback, useEffect, useRef, useState } from 'react';

import { getMe, login as apiLogin, logout as apiLogout } from '@/api/auth';

export const AuthContext = createContext(null);

function delay(ms) {
    return new Promise((resolve) => {
        window.setTimeout(resolve, ms);
    });
}

export function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const userRef = useRef(null);

    useEffect(() => {
        userRef.current = user;
    }, [user]);

    useEffect(() => {
        let cancelled = false;
        const controller = new AbortController();
        const timeoutId = window.setTimeout(() => controller.abort(), 5000);

        getMe({ signal: controller.signal })
            .then((data) => {
                if (!cancelled) {
                    setUser(data);
                }
            })
            .catch(() => {
                if (!cancelled) {
                    setUser((currentUser) => currentUser ?? null);
                }
            })
            .finally(() => {
                window.clearTimeout(timeoutId);
                if (!cancelled) {
                    setIsLoading(false);
                }
            });

        return () => {
            cancelled = true;
            controller.abort();
            window.clearTimeout(timeoutId);
        };
    }, []);

    useEffect(() => {
        const handleLogout = () => {
            setUser(null);
        };

        window.addEventListener('auth:logout', handleLogout);
        return () => window.removeEventListener('auth:logout', handleLogout);
    }, []);

    const refreshSession = useCallback(async ({ clearOnError = true } = {}) => {
        try {
            const me = await getMe();
            setUser(me);
            return me;
        } catch (error) {
            if (clearOnError) {
                setUser(null);
            }
            throw error;
        }
    }, []);

    const waitForSession = useCallback(async ({ attempts = 3, delayMs = 500 } = {}) => {
        if (userRef.current) {
            return userRef.current;
        }

        let lastError = null;

        for (let attempt = 0; attempt < attempts; attempt += 1) {
            if (userRef.current) {
                return userRef.current;
            }

            try {
                return await refreshSession({ clearOnError: false });
            } catch (error) {
                lastError = error;
                if (attempt < attempts - 1) {
                    await delay(delayMs);
                }
            }
        }

        setUser((currentUser) => currentUser ?? null);
        throw lastError;
    }, [refreshSession]);

    const login = useCallback(async (credentials) => {
        await apiLogin(credentials);
        return waitForSession({ attempts: 3, delayMs: 500 });
    }, [waitForSession]);

    const logout = useCallback(async () => {
        try {
            await apiLogout();
        } finally {
            setUser(null);
        }
    }, []);

    return (
        <AuthContext.Provider
            value={{
                user,
                isLoading,
                isAuthenticated: !!user,
                login,
                logout,
                refreshSession,
                waitForSession,
            }}
        >
            {children}
        </AuthContext.Provider>
    );
}
