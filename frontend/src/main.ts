import './assets/styles/variables.css'
import './assets/styles/main.css'
import 'bootstrap/dist/css/bootstrap.min.css';

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router/router';

import App from './App.vue'
import { useSetupStore } from "@/stores/setup.ts";
import { useAuthStore } from "@/stores/auth.ts";
import { useThemeStore } from "@/stores/theme.ts";
import { useCertificateStore } from "@/stores/certificates.ts";
import { useUserStore } from "@/stores/users.ts";
import { useCAStore } from "@/stores/ca.ts";

// Periodic state sync interval (5 minutes)
const STATE_SYNC_INTERVAL = 5 * 60 * 1000; // 5 minutes in milliseconds

async function initApp() {
    const pinia = createPinia();
    const app = createApp(App);

    // Initialize Pinia before mounting
    app.use(pinia);

    // Initialize the stores
    const setupStore = useSetupStore();
    await setupStore.init()

    const authStore = useAuthStore();
    await authStore.init();

    const themeStore = useThemeStore();
    themeStore.init();

    app.use(router);

    app.mount('#app');

    // Start periodic state synchronization for long-running sessions
    startPeriodicStateSync();
}

// Periodic state synchronization for long-running sessions
function startPeriodicStateSync() {
    setInterval(async () => {
        try {
            const authStore = useAuthStore();
            const certStore = useCertificateStore();
            const userStore = useUserStore();
            const caStore = useCAStore();

            // Only sync if user is authenticated
            if (authStore.isAuthenticated) {
                // Sync critical state data
                await Promise.allSettled([
                    certStore.fetchCertificates(),
                    caStore.fetchCAList(),
                    // Only sync user list for admins to avoid unnecessary API calls
                    authStore.isAdmin ? userStore.fetchUsers() : Promise.resolve(),
                ]);

                console.debug('Periodic state sync completed');
            }
        } catch (error) {
            console.warn('Periodic state sync failed:', error);
            // Don't throw - periodic sync should not break the app
        }
    }, STATE_SYNC_INTERVAL);
}

initApp().catch((err) => {
    console.error('Failed to initialize app:', err);
});
