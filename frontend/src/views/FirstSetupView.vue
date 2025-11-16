<template>
  <div class="container d-flex justify-content-center align-items-center min-vh-100 py-4">
    <div class="card p-4 shadow" style="max-width: 600px; width: 100%; max-height: 90vh; overflow-y: auto;">
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
          <label class="form-label">Certificate Authority</label>
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
              Upload Existing CA
            </label>
          </div>
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
              Create Root CA
            </label>
          </div>
        </div>

        <!-- Root CA Server Mode -->
        <div v-if="ca_type === 'self_signed'" class="mb-3">
          <div class="form-check">
            <input
                class="form-check-input"
                type="checkbox"
                id="is_root_ca"
                v-model="is_root_ca"
            />
            <label class="form-check-label" for="is_root_ca">
              <strong>Set up as Root CA Server</strong>
            </label>
            <div class="form-text">
              When enabled, this instance will only issue subordinate CA certificates.
              Client and server certificates must be issued by importing subordinate CAs into other instances.
            </div>
          </div>
        </div>

        <!-- Distinguished Name Configuration for Root CA -->
        <div v-if="ca_type === 'self_signed'">
          <h6 class="mb-3">Certificate Authority Configuration</h6>

          <!-- Distinguished Name Fields -->
          <div class="row">
            <div class="col-md-6 mb-3">
              <label for="countryName" class="form-label">Country Name (2 letter code)</label>
              <input
                  type="text"
                  class="form-control"
                  id="countryName"
                  v-model="countryName"
                  required
                  maxlength="2"
                  placeholder="QA"
              />
            </div>
            <div class="col-md-6 mb-3">
              <label for="stateOrProvinceName" class="form-label">State or Province Name</label>
              <input
                  type="text"
                  class="form-control"
                  id="stateOrProvinceName"
                  v-model="stateOrProvinceName"
                  required
                  placeholder="Doha"
              />
            </div>
          </div>

          <div class="row">
            <div class="col-md-6 mb-3">
              <label for="localityName" class="form-label">Locality Name</label>
              <input
                  type="text"
                  class="form-control"
                  id="localityName"
                  v-model="localityName"
                  required
                  placeholder="Bin Omran"
              />
            </div>
            <div class="col-md-6 mb-3">
              <label for="organizationName" class="form-label">Organization Name</label>
              <input
                  type="text"
                  class="form-control"
                  id="organizationName"
                  v-model="organizationName"
                  required
                  placeholder="Your Organization"
              />
            </div>
          </div>

          <div class="row">
            <div class="col-md-6 mb-3">
              <label for="organizationalUnitName" class="form-label">Organizational Unit (Optional)</label>
              <input
                  type="text"
                  class="form-control"
                  id="organizationalUnitName"
                  v-model="organizationalUnitName"
                  placeholder="IT Department"
              />
            </div>
            <div class="col-md-6 mb-3">
              <label for="commonName" class="form-label">Common Name</label>
              <input
                  type="text"
                  class="form-control"
                  id="commonName"
                  v-model="commonName"
                  required
                  placeholder="rootca.yourdomain.com"
              />
            </div>
          </div>

          <div class="row">
            <div class="col-md-6 mb-3">
              <label for="emailAddress" class="form-label">Email Address</label>
              <input
                  type="email"
                  class="form-control"
                  id="emailAddress"
                  v-model="emailAddress"
                  required
                  placeholder="pki@yourdomain.com"
              />
            </div>
            <div class="col-md-6 mb-3">
              <label for="ca_validity_in_years" class="form-label">Validity (Years)</label>
              <input
                  type="number"
                  class="form-control"
                  id="ca_validity_in_years"
                  v-model.number="ca_validity_in_years"
                  required
                  min="1"
                  max="30"
              />
            </div>
          </div>

          <div class="mb-3">
            <label for="ca_name" class="form-label">CA Display Name (Optional)</label>
            <input
                type="text"
                class="form-control"
                id="ca_name"
                v-model="ca_name"
                placeholder="Defaults to Common Name if left empty"
            />
            <small class="text-muted">Optional display name for the CA. If left empty, the Common Name will be used.</small>
          </div>

          <!-- Advanced CA Configuration -->
          <h6 class="mb-3 mt-4">Advanced CA Configuration</h6>

          <div class="mb-3">
            <label class="form-label">Key Type</label>
            <div class="form-check">
              <input
                  class="form-check-input"
                  type="radio"
                  id="keyTypeRSA"
                  value="RSA"
                  v-model="keyType"
                  required
              />
              <label class="form-check-label" for="keyTypeRSA">
                RSA
              </label>
            </div>
            <div class="form-check">
              <input
                  class="form-check-input"
                  type="radio"
                  id="keyTypeECDSA"
                  value="ECDSA"
                  v-model="keyType"
                  required
              />
              <label class="form-check-label" for="keyTypeECDSA">
                ECDSA
              </label>
            </div>
          </div>

          <div class="row">
            <div class="col-md-6 mb-3">
              <label for="keySize" class="form-label">Key Size</label>
              <select
                  class="form-select"
                  id="keySize"
                  v-model="keySize"
                  required
              >
                <option v-if="keyType === 'RSA'" value="2048">2048</option>
                <option v-if="keyType === 'RSA'" value="4096">4096</option>
                <option v-if="keyType === 'ECDSA'" value="P-256">P-256</option>
                <option v-if="keyType === 'ECDSA'" value="P-521">P-521</option>
              </select>
            </div>
            <div class="col-md-6 mb-3">
              <label for="hashAlgorithm" class="form-label">Hash Algorithm</label>
              <select
                  class="form-select"
                  id="hashAlgorithm"
                  v-model="hashAlgorithm"
                  required
              >
                <option value="sha256">SHA-256</option>
                <option value="sha512">SHA-512</option>
              </select>
            </div>
          </div>

          <div class="row">
            <div class="col-md-6 mb-3">
              <label for="crlValidityDays" class="form-label">CRL Validity (days)</label>
              <input
                  type="number"
                  class="form-control"
                  id="crlValidityDays"
                  v-model.number="crlValidityDays"
                  required
                  min="1"
                  max="365"
              />
            </div>
            <div class="col-md-6 mb-3">
              <label for="pathLength" class="form-label">Maximum intermediate CA levels</label>
              <input
                  type="number"
                  class="form-control"
                  id="pathLength"
                  v-model.number="pathLength"
                  required
                  min="0"
                  max="10"
              />
              <!-- <small class="text-muted">Maximum number of intermediate CA levels</small> -->
            </div>
          </div>

          <div class="mb-3">
            <label for="aiaUrl" class="form-label">AIA URL (where CA certificate can be downloaded)</label>
            <input
                type="url"
                class="form-control"
                id="aiaUrl"
                v-model="aiaUrl"
                placeholder="http://your-ca.example.com/certs/ca.cert.pem"
            />
            <!-- <small class="text-muted">URL </small> -->
          </div>

          <div class="mb-3">
            <label for="cdpUrl" class="form-label">CDP URL (where Certificate Revocation List can be downloaded)</label>
            <input
                type="url"
                class="form-control"
                id="cdpUrl"
                v-model="cdpUrl"
                placeholder="http://your-ca.example.com/crl/ca.crl.pem"
            />
            <!-- <small class="text-muted">URL where Certificate Revocation List can be downloaded</small> -->
          </div>

          <div class="alert alert-info">
            <i class="bi bi-info-circle me-2"></i>
            These settings configure the Distinguished Name (DN) and advanced certificate extensions for your Root CA certificate, following standard X.509 certificate practices. Default values are loaded from the OpenSSL configuration.
          </div>
        </div>

        <div v-if="ca_type === 'upload'" class="mb-3">
          <div class="file-input-wrapper">
            <input
                id="pfx_file"
                type="file"
                @change="handleFileChange"
                class="form-control file-input-hidden"
                accept=".pfx,.p12"
                required
            />
            <div class="file-input-custom">
              <button type="button" class="btn btn-outline-secondary btn-sm me-2" @click="triggerFileInput">Select</button>
              <span class="file-input-text">{{ selectedFileName || 'Upload CA certificate in PKCS12 (.pfx/.p12) format' }}</span>
            </div>
          </div>
        </div>

        <div v-if="ca_type === 'upload'" class="mb-3">
          <input
              id="pfx_password"
              type="password"
              v-model="pfx_password"
              class="form-control"
              placeholder="Enter Password (leave empty if none)"
          />
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
import { ref, watch } from 'vue';
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
const ca_type = ref('upload'); // Default to upload existing CA
const is_root_ca = ref(false);
const pfx_file = ref<File | null>(null);
const pfx_password = ref('');
const selectedFileName = ref<string>('');

// DN fields with defaults from openssl_rootca.cnf
const countryName = ref('QA');
const stateOrProvinceName = ref('Doha');
const localityName = ref('Bin Omran');
const organizationName = ref('Yawal');
const organizationalUnitName = ref('');
const commonName = ref('rootca.abc.io');
const emailAddress = ref('pki@abc.io');

// Additional CA configuration fields from openssl.cnf
const keyType = ref('RSA');
const keySize = ref('2048');
const hashAlgorithm = ref('sha256');

// Watch for key type changes and reset key size to appropriate default
watch(keyType, (newKeyType: string) => {
  if (newKeyType === 'RSA' && keySize.value == '' ) {
    keySize.value = '2048';
  } else if (newKeyType === 'ECDSA' && keySize.value == '') {
    keySize.value = 'P-256';
  }
  if (hashAlgorithm.value == '' ) {
    hashAlgorithm.value = 'sha256';
  }
});
const crlValidityDays = ref(30);
const pathLength = ref(1);
const aiaUrl = ref('http://rootca.abc.io/certs/ca.cert.pem');
const cdpUrl = ref('http://rootca.abc.io/crl/ca.crl.pem');

const handleFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];

  if (file) {
    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      errorMessage.value = 'File size must be less than 10MB';
      target.value = '';
      pfx_file.value = null;
      selectedFileName.value = '';
      return;
    }

    // Validate file type
    const validTypes = ['application/x-pkcs12', 'application/pkcs12'];
    if (!validTypes.includes(file.type) && !file.name.toLowerCase().endsWith('.pfx') && !file.name.toLowerCase().endsWith('.p12')) {
      errorMessage.value = 'Please select a valid PKCS#12 file (.pfx or .p12)';
      target.value = '';
      pfx_file.value = null;
      selectedFileName.value = '';
      return;
    }

    pfx_file.value = file;
    selectedFileName.value = file.name;
    errorMessage.value = '';
  } else {
    pfx_file.value = null;
    selectedFileName.value = '';
  }
};

const triggerFileInput = () => {
  const fileInput = document.getElementById('pfx_file') as HTMLInputElement;
  if (fileInput) {
    fileInput.click();
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
    if (ca_type.value === 'self_signed' && !commonName.value.trim()) {
      errorMessage.value = 'Common Name is required for self-signed certificates';
      return;
    }
    if (ca_type.value === 'upload' && !pfx_file.value) {
      errorMessage.value = 'Please select a PKCS#12 file';
      return;
    }

    const setupData = {
      name: username.value.trim(),
      email: email.value.trim(),
      ca_name: ca_name.value.trim() || (ca_type.value === 'self_signed' ? commonName.value.trim() : (ca_type.value === 'upload' ? 'Imported CA' : '')),
      ca_validity_in_years: ca_validity_in_years.value,
      password: password.value.trim() || null,
      ca_type: ca_type.value as 'self_signed' | 'upload',
      key_type: ca_type.value === 'self_signed' ? keyType.value : undefined,
      key_size: ca_type.value === 'self_signed' ? keySize.value : undefined,
      hash_algorithm: ca_type.value === 'self_signed' ? hashAlgorithm.value : undefined,
      pfx_file: pfx_file.value || undefined,
      pfx_password: pfx_password.value.trim() || undefined,
      // DN fields for self-signed CA
      countryName: ca_type.value === 'self_signed' ? countryName.value : undefined,
      stateOrProvinceName: ca_type.value === 'self_signed' ? stateOrProvinceName.value : undefined,
      localityName: ca_type.value === 'self_signed' ? localityName.value : undefined,
      organizationName: ca_type.value === 'self_signed' ? organizationName.value : undefined,
      organizationalUnitName: ca_type.value === 'self_signed' ? organizationalUnitName.value : undefined,
      commonName: ca_type.value === 'self_signed' ? commonName.value : undefined,
      emailAddress: ca_type.value === 'self_signed' ? emailAddress.value : undefined,
      // Root CA mode
      is_root_ca: is_root_ca.value,
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

<style scoped>
.file-input-wrapper {
  position: relative;
}

.file-input-hidden {
  position: absolute;
  opacity: 0;
  pointer-events: none;
  width: 100%;
  height: 100%;
}

.file-input-custom {
  display: flex;
  align-items: center;
  padding: 0.375rem 0.75rem;
  border: 1px solid #ced4da;
  border-radius: 0.375rem;
  background-color: #fff;
  min-height: 38px;
}

.file-input-custom:focus-within {
  border-color: #86b7fe;
  outline: 0;
  box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
}

.file-input-text {
  flex: 1;
  color: #6c757d;
  font-size: 0.875rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.file-input-custom .btn {
  flex-shrink: 0;
}
</style>
