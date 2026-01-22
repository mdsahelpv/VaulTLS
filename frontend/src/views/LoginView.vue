<template>
  <div class="container d-flex justify-content-center align-items-center vh-100">
    <div class="card shadow-lg">
      <img
        src="@assets/logo.png"
        alt="Logo"
        class="logo d-block mx-auto"
      >
      
      <form
        v-if="setupStore.passwordAuthEnabled"
        @submit.prevent="submitLogin"
      >
        <div class="mb-3">
          <label
            for="email"
            class="form-label"
          >E-Mail</label>
          <input
            id="email"
            v-model="email"
            type="email"
            class="form-control"
            placeholder="name@example.com"
            required
          >
        </div>
        <div class="mb-3">
          <label
            for="password"
            class="form-label"
          >Password</label>
          <div class="input-group">
            <input
              id="password"
              v-model="password"
              :type="showPassword ? 'text' : 'password'"
              class="form-control"
              placeholder="••••••••"
              autocomplete="current-password"
              required
            >
            <button
              type="button"
              class="btn btn-outline-secondary"
              :title="showPassword ? 'Hide password' : 'Show password'"
              @click="showPassword = !showPassword"
            >
              <img
                :src="showPassword ? '/images/eye-hidden.png' : '/images/eye-open.png'"
                alt="Toggle"
                style="width: 16px; height: 16px; opacity: 0.6;"
              >
            </button>
          </div>
        </div>
        <button
          type="submit"
          class="btn btn-primary w-100 login-btn"
          :disabled="isLoading"
        >
          <span
            v-if="isLoading"
            class="spinner-border spinner-border-sm me-2"
          />
          Login
        </button>
        <p
          v-if="loginError"
          class="text-danger mt-3"
        >
          {{ loginError }}
        </p>
      </form>

      <p
        v-else
        class="text-center text-warning"
      >
        Password authentication is disabled.
      </p>

      <div
        v-if="setupStore.oidcUrl"
        class="mt-4 pt-3 border-top"
      >
        <button
          class="btn btn-outline-secondary w-100 oidc-btn"
          @click="redirectToOIDC"
        >
          <i class="bi bi-box-arrow-in-right me-2" /> Login with OAuth
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useAuthStore } from '../stores/auth';
import router from "@/router/router.ts";
import {useSetupStore} from "@/stores/setup.ts";

const email = ref('');
const password = ref('');
const loginError = ref('');
const isLoading = ref(false);
const showPassword = ref(false);
const authStore = useAuthStore();
const setupStore = useSetupStore();

const submitLogin = async () => {
  loginError.value = '';
  isLoading.value = true;
  const success = await authStore.login(email.value, password.value);
  isLoading.value = false;
  if (!success) {
    loginError.value = 'Invalid email or password.';
  } else {
    await router.push("Overview");
  }
};

const redirectToOIDC = () => {
  if (setupStore.oidcUrl) {
    window.location.href = `${window.location.origin}/api/auth/oidc/login`;
  }
};
</script>

<style scoped>
.container {
  min-width: 100vw;
  background-color: var(--color-page-background);
}

.card {
  max-width: 550px;
  width: 100%;
  padding: var(--spacing-xxl) !important;
  border: 1px solid var(--color-border);
}

.logo {
  max-width: 120px;
  margin-bottom: var(--spacing-xxl);
  animation: logoPulse 2s ease-in-out infinite;
  transition: transform 0.3s ease;
}

.logo:hover {
  transform: scale(1.05);
  animation-play-state: paused;
}

.form-label {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
  font-size: 13px;
  margin-bottom: 6px;
}

.input-group .btn {
  border: 1px solid var(--color-border) !important;
  border-left: none !important;
}

.login-btn {
  margin-top: var(--spacing-lg);
  padding: 12px !important;
  font-size: 16px;
}

.oidc-btn {
  padding: 12px !important;
  font-size: 14px;
}

.text-danger {
  font-size: 13px;
  text-align: center;
}

.border-top {
  border-top: 1px solid var(--color-border) !important;
}

/* Logo Animations */
@keyframes logoEntrance {
  0% {
    opacity: 0;
    transform: translateY(-20px) scale(0.8);
  }
  50% {
    opacity: 0.7;
    transform: translateY(-5px) scale(1.05);
  }
  100% {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@keyframes logoPulse {
  0%, 100% {
    transform: scale(1);
    filter: brightness(1) hue-rotate(0deg) saturate(1);
  }
  25% {
    transform: scale(1.01);
    filter: brightness(1.05) hue-rotate(5deg) saturate(1.1);
  }
  50% {
    transform: scale(1.02);
    filter: brightness(1.1) hue-rotate(10deg) saturate(1.2);
  }
  75% {
    transform: scale(1.01);
    filter: brightness(1.05) hue-rotate(5deg) saturate(1.1);
  }
}
</style>
