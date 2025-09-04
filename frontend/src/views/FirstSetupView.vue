<template>
  <div class="container d-flex justify-content-center align-items-center vh-100">
    <div class="card p-4 shadow" style="max-width: 400px; width: 100%;">
      <h1 class="text-center mb-4">Hello</h1>

      <!-- Show notice if OIDC is enabled -->
      <div v-if="setupStore.oidcUrl" class="alert alert-info text-center">
        OAuth (OIDC) is configured. You can still set a password for local login if desired.
      </div>

      <form @submit.prevent="setupPassword">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input
              id="username"
              type="text"
              v-model="username"
              class="form-control"
              required
          />
        </div>

        <!-- Password field moved here, next to username -->
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input
              id="password"
              type="password"
              v-model="password"
              class="form-control"
              autocomplete="new-password"
              :required="!setupStore.oidcUrl"
          />
          <small class="text-muted">
            {{ setupStore.oidcUrl ? "You can leave this empty if using OAuth (OIDC)." : "Required for local login." }}
          </small>
        </div>

        <div class="mb-3">
          <label for="email" class="form-label">E-Mail</label>
          <input
              id="email"
              type="text"
              v-model="email"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label for="ca_name" class="form-label">Name of CA entity</label>
          <input
              id="ca_name"
              type="text"
              v-model="ca_name"
              class="form-control"
              :required="ca_type === 'self_signed'"
              :placeholder="ca_type === 'upload' ? 'Optional - will use certificate subject if empty' : ''"
          />
          <small v-if="ca_type === 'upload'" class="text-muted">
            Leave empty to use the subject name from the uploaded certificate
          </small>
        </div>

        <div class="mb-3">
          <label for="ca_validity_in_years" class="form-label">Validity of CA in years</label>
          <input
              id="ca_validity_in_years"
              type="number"
              v-model="ca_validity_in_years"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label class="form-label">CA Certificate Type</label>
          <div class="form-check">
            <input
                class="form-check-input"
                type="radio"
                id="ca_type_self_signed"
                value="self_signed"
                v-model="ca_type"
                required
            />
            <label class="form-check-label" for="ca_type_self_signed">
              Generate Self-Signed CA
            </label>
          </div>
          <div class="form-check">
            <input
                class="form-check-input"
                type="radio"
                id="ca_type_upload"
                value="upload"
                v-model="ca_type"
                required
            />
            <label class="form-check-label" for="ca_type_upload">
              Upload Existing CA (.pfx/.p12)
            </label>
          </div>
        </div>

        <div v-if="ca_type === 'upload'" class="mb-3">
          <label for="pfx_file" class="form-label">PKCS#12 File (.pfx/.p12)</label>
          <input
              id="pfx_file"
              type="file"
              @change="handleFileChange"
              class="form-control"
              accept=".pfx,.p12"
              required
          />
          <small class="text-muted">Upload your existing CA certificate in PKCS#12 format</small>
        </div>

        <div v-if="ca_type === 'upload'" class="mb-3">
          <label for="pfx_password" class="form-label">Keystore Password</label>
          <input
              id="pfx_password"
              type="password"
              v-model="pfx_password"
              class="form-control"
              placeholder="Enter password for the PKCS#12 file"
          />
          <small class="text-muted">Leave empty if the keystore is not password-protected</small>
        </div>

        <button type="submit" class="btn btn-primary w-100">
          Complete Setup
        </button>

        <p v-if="errorMessage" class="text-danger mt-3">
          {{ errorMessage }}
        </p>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import router from '../router/router';
import { setup } from "@/api/auth.ts";
import {useSetupStore} from "@/stores/setup.ts";
import {hashPassword} from "@/utils/hash.ts";

const setupStore = useSetupStore();

const username = ref('');
const email = ref('');
const ca_name = ref('');
const ca_validity_in_years = ref(10);
const password = ref('');
const errorMessage = ref('');
const ca_type = ref('self_signed');
const pfx_file = ref<File | null>(null);
const pfx_password = ref('');

const handleFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];

  if (file) {
    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      errorMessage.value = 'File size must be less than 10MB';
      target.value = '';
      pfx_file.value = null;
      return;
    }

    // Validate file type
    const validTypes = ['application/x-pkcs12', 'application/pkcs12'];
    if (!validTypes.includes(file.type) && !file.name.toLowerCase().endsWith('.pfx') && !file.name.toLowerCase().endsWith('.p12')) {
      errorMessage.value = 'Please select a valid PKCS#12 file (.pfx or .p12)';
      target.value = '';
      pfx_file.value = null;
      return;
    }

    pfx_file.value = file;
    errorMessage.value = '';
  } else {
    pfx_file.value = null;
  }
};

const setupPassword = async () => {
  try {
    // Validate required fields for upload option
    if (ca_type.value === 'upload' && !pfx_file.value) {
      errorMessage.value = 'Please select a PKCS#12 file';
      return;
    }

    let hash = password.value ? await hashPassword(password.value) : null;

    // Validate required fields
    if (!username.value.trim()) {
      errorMessage.value = 'Username is required';
      return;
    }
    if (!email.value.trim()) {
      errorMessage.value = 'Email is required';
      return;
    }
    if (ca_type.value === 'self_signed' && !ca_name.value.trim()) {
      errorMessage.value = 'CA name is required for self-signed certificates';
      return;
    }
    if (ca_type.value === 'upload' && !pfx_file.value) {
      errorMessage.value = 'Please select a PKCS#12 file';
      return;
    }

    const setupData = {
      name: username.value.trim(),
      email: email.value.trim(),
      ca_name: ca_name.value.trim() || (ca_type.value === 'upload' ? 'Imported CA' : ''),
      ca_validity_in_years: ca_validity_in_years.value,
      password: password.value.trim() || null,
      ca_type: ca_type.value as 'self_signed' | 'upload',
      pfx_file: pfx_file.value || undefined,
      pfx_password: pfx_password.value.trim() || undefined,
    };

    await setup(setupData);
    await setupStore.reload();
    await router.replace({ name: 'Login' });
  } catch (err) {
    if (err instanceof Error) {
      errorMessage.value = err.message;
    } else {
      errorMessage.value = 'Failed to set up.';
    }
  }
};
</script>
