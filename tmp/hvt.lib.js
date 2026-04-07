import { API_KEY_CANONICAL_SCOPES, HVTApiError, HVTClient } from 'hvt-sdk';

export const hvt = new HVTClient({
    baseUrl: import.meta.env.VITE_API_URL,
    fetch: (...args) => fetch(...args),
});

export { API_KEY_CANONICAL_SCOPES, HVTApiError, HVTClient };
