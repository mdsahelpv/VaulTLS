// Environment variable types for type safety

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_APP_TITLE?: string;
  readonly VITE_APP_VERSION?: string;
  readonly DEV: boolean;
  readonly PROD: boolean;
  readonly SSR: boolean;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

// Global environment access with proper typing
export const env = {
  get apiBaseUrl(): string {
    // Priority 1: Explicit environment variable
    const explicitUrl = import.meta.env.VITE_API_BASE_URL;
    if (explicitUrl) {
      return explicitUrl;
    }

    // Priority 2: In development, determine API URL dynamically
    // This helps when accessing via IP address instead of localhost
    if (import.meta.env.DEV) {
      try {
        // If we're in a browser environment, construct the API URL based on current location
        if (typeof window !== 'undefined') {
          const protocol = window.location.protocol;
          const hostname = window.location.hostname;
          const apiUrl = `${protocol}//${hostname}:8000`;

          // Log the detected API URL for debugging
          console.log('🔧 VaulTLS: Detected API URL:', apiUrl, 'from location:', window.location.href);

          return apiUrl;
        }
      } catch (e) {
        // Fallback if window is not available
        console.log('🔧 VaulTLS: Window not available, using fallback');
      }
      // Final fallback for development
      console.log('🔧 VaulTLS: Using localhost fallback');
      return 'http://localhost:8000';
    }

    // Priority 3: In production, use relative URLs (assume same origin)
    // This works when frontend and backend are served from the same server
    return '';
  },

  get isDev(): boolean {
    return import.meta.env.DEV;
  },

  get isProd(): boolean {
    return import.meta.env.PROD;
  },

  get appTitle(): string {
    return import.meta.env.VITE_APP_TITLE || 'VaulTLS';
  },

  get appVersion(): string {
    return import.meta.env.VITE_APP_VERSION || '1.0.0';
  },
};
