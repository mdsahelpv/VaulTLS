<template>
  <div class="container d-flex justify-content-center align-items-center min-vh-100 py-4">
    <div class="card p-4 shadow" style="max-width: 750px; width: 100%; max-height: 90vh; overflow-y: auto;">
      <h1 class="text-center mb-4">SETUP</h1>

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
          <div class="input-group">
            <input
                id="password"
                :type="showPassword ? 'text' : 'password'"
                v-model="password"
                class="form-control"
                autocomplete="new-password"
                :required="!setupStore.oidcUrl"
            />
            <button
                class="btn btn-outline-secondary"
                type="button"
                @click="showPassword = !showPassword"
                tabindex="-1"
            >
              <img
                  :src="`/images/${showPassword ? 'eye-hidden' : 'eye-open'}.png`"
                  alt="Toggle password visibility"
                  width="16"
                  height="16"
              />
            </button>
          </div>
          <small class="text-muted">
            {{ setupStore.oidcUrl ? "You can leave this empty if using OAuth (OIDC)." : "Required for local login." }}
          </small>
        </div>

        <div class="mb-3">
          <label for="email" class="form-label">E-Mail</label>
          <input
              id="email"
              type="email"
              v-model="email"
              class="form-control"
              maxlength="254"
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
            <!-- <input
                class="form-check-input"
                type="checkbox"
                id="is_root_ca"
                v-model="is_root_ca"
            /> -->
            <label class="form-check-label" for="is_root_ca">
              <strong>SubCA signing Only</strong>
            </label>
            <div class="form-text">
              This instance issues Subordinate CA (not the Server/Client) certificates.
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
                :placeholder="`${getCurrentBaseUrl()}/api/certificates/ca/download`"
            />
            <small class="text-muted">Optional. Used by clients to download the CA certificate.</small>
          </div>

          <div class="mb-3">
            <label for="cdpUrl" class="form-label">CDP URL (where Certificate Revocation List can be downloaded)</label>
            <input
                type="url"
                class="form-control"
                id="cdpUrl"
                v-model="cdpUrl"
                :placeholder="`${getCurrentBaseUrl()}/api/certificates/crl`"
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
          <label for="pfx_password" class="form-label">PFX Password</label>
          <div class="input-group">
            <input
                id="pfx_password"
                :type="showPfxPassword ? 'text' : 'password'"
                v-model="pfx_password"
                class="form-control"
                placeholder="Enter Password (leave empty if none)"
            />
            <button
                class="btn btn-outline-secondary"
                type="button"
                @click="showPfxPassword = !showPfxPassword"
                tabindex="-1"
            >
              <img
                  :src="`/images/${showPfxPassword ? 'eye-hidden' : 'eye-open'}.png`"
                  alt="Toggle PFX password visibility"
                  width="16"
                  height="16"
              />
            </button>
          </div>
        </div>

        <!-- Certificate Validation for Upload Option -->
        <div v-if="ca_type === 'upload'" class="mb-3">
          <button
              type="button"
              @click="validateCertificate"
              :disabled="!pfx_file || isValidating"
              class="btn btn-outline-secondary me-2"
          >
            <span v-if="isValidating" class="spinner-border spinner-border-sm me-2" role="status"></span>
            {{ isValidating ? 'Validating...' : 'Validate Certificate' }}
          </button>
          <small class="text-muted">Validate your PKCS#12 file before proceeding with setup</small>
          <div v-if="validationStatus === 'success' && !detailedValidation.validations" class="alert alert-success mt-2">
            <i class="bi bi-check-circle me-2"></i>Certificate validated successfully!
          </div>
          <div v-else-if="validationStatus === 'success' && detailedValidation.validations" class="alert alert-success mt-2">
            <i class="bi bi-check-circle me-2"></i>
            <strong>Certificate Validated Successfully!</strong>
            <div class="mt-2">
              <small class="text-success">Validation completed with the following checks:</small>
              <div class="validation-steps mt-2">
                <div v-for="check in detailedValidation.validations" :key="check.check_name" class="validation-step">
                  <span v-if="check.passed" class="validation-status-success">✓</span>
                  <span v-else class="validation-status-error">✗</span>
                  {{ check.description }}
                </div>
              </div>
            </div>
          </div>
          <div v-if="validationStatus === 'error'" class="alert alert-danger mt-2">
            <i class="bi bi-exclamation-triangle me-2"></i>
            <strong>Certificate Validation Failed</strong>
            <div v-if="validationError">{{ validationError }}</div>
            <div v-else-if="detailedValidation.validations" class="mt-2">
              <small class="text-danger">Validation failed with the following issues:</small>
              <div class="validation-steps mt-2">
                <div v-for="check in detailedValidation.validations" :key="check.check_name" class="validation-step">
                  <span v-if="check.passed" class="validation-status-success">✓</span>
                  <span v-else class="validation-status-error">✗</span>
                  {{ check.description }}
                </div>
              </div>
            </div>
          </div>
        </div>

        <button type="submit" class="btn btn-primary w-100" :disabled="ca_type === 'upload' && validationStatus !== 'success'">
          Complete Setup
        </button>

        <div v-if="ca_type === 'upload' && validationStatus !== 'success'" class="text-muted mt-2">
          <i class="bi bi-info-circle me-2"></i>Please validate your certificate first
        </div>

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
import { setup, validate_pfx, type ValidationCheck } from "@/api/auth.ts";
import {useSetupStore} from "@/stores/setup.ts";

// Password visibility state
const showPassword = ref(false);
const showPfxPassword = ref(false);

const setupStore = useSetupStore();

const username = ref('');
const email = ref('');
const ca_name = ref('');
const ca_validity_in_years = ref(10);
const password = ref('');
const errorMessage = ref('');
const ca_type = ref('upload'); // Default to upload existing CA
const is_root_ca = ref(false); // Default to Root CA mode for self-signed CA
const pfx_file = ref<File | null>(null);
const pfx_password = ref('');
const selectedFileName = ref<string>('');

// Certificate validation state
const isValidating = ref(false);
const validationStatus = ref<'none' | 'success' | 'error'>('none');
const validationError = ref('');
const detailedValidation = ref<{ validations?: ValidationCheck[]; error?: string }>({});

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
const keySize = ref('4096');
const hashAlgorithm = ref('sha256');

// Watch for key type changes and reset key size to appropriate default
watch(keyType, (newKeyType: string) => {
  if (newKeyType === 'RSA') {
    // Set default RSA key size if previous value wasn't RSA or was empty
    if (keySize.value === '' || keySize.value === 'P-256' || keySize.value === 'P-521') {
      keySize.value = '4096';
    }
  } else if (newKeyType === 'ECDSA') {
    // Set default ECDSA curve if previous value wasn't ECDSA or was empty
    if (keySize.value === '' || keySize.value === '2048' || keySize.value === '4096') {
      keySize.value = 'P-256';
    }
  }
  if (hashAlgorithm.value === '') {
    hashAlgorithm.value = 'sha256';
  }
});

// Auto-select Root CA Server mode when creating a root CA
watch(ca_type, (newCaType: string) => {
  if (newCaType === 'self_signed') {
    is_root_ca.value = true;
  } else if (newCaType === 'upload') {
    is_root_ca.value = false;
  }
});
const crlValidityDays = ref(30);
const pathLength = ref(1);

// Function to get current base URL
const getCurrentBaseUrl = () => {
  const origin = window.location.origin;
  return origin || 'http://localhost:8000';
};

// Auto-fill CRL and AIA URLs with actual application endpoints
const cdpUrl = ref(`${getCurrentBaseUrl()}/api/certificates/crl`);
const aiaUrl = ref(`${getCurrentBaseUrl()}/api/certificates/ca/download`);

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

// Reset validation when file changes
watch(pfx_file, () => {
  validationStatus.value = 'none';
  validationError.value = '';
});

// Reset validation when password changes
watch(pfx_password, () => {
  validationStatus.value = 'none';
  validationError.value = '';
});

const validateCertificate = async () => {
  if (!pfx_file.value) {
    return;
  }

  isValidating.value = true;
  validationStatus.value = 'none';
  validationError.value = '';
  detailedValidation.value = {};

  try {
    const result = await validate_pfx(pfx_file.value, pfx_password.value || undefined);

    if (result.valid) {
      validationStatus.value = 'success';
      detailedValidation.value = {
        validations: result.validation_result?.validations || [],
      };
    } else {
      validationStatus.value = 'error';
      validationError.value = result.error || 'Unknown validation error';
      detailedValidation.value = {
        validations: result.validation_result?.validations || [],
        error: result.validation_result?.error || result.error
      };
    }
  } catch (err) {
    validationStatus.value = 'error';
    validationError.value = err instanceof Error ? err.message : 'Failed to validate certificate';
    detailedValidation.value = { error: err instanceof Error ? err.message : 'Unknown error' };
  } finally {
    isValidating.value = false;
  }
};

const setupPassword = async () => {
  try {
    // Validate required fields for upload option
    if (ca_type.value === 'upload' && !pfx_file.value) {
      errorMessage.value = 'Please select a PKCS#12 file';
      return;
    }

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
      // Certificate extensions for CA
      aia_url: ca_type.value === 'self_signed' ? (aiaUrl.value || `${getCurrentBaseUrl()}/api/certificates/ca/download`) : undefined,
      cdp_url: ca_type.value === 'self_signed' ? (cdpUrl.value || `${getCurrentBaseUrl()}/api/certificates/crl`) : undefined,
      crl_validity_days: ca_type.value === 'self_signed' ? crlValidityDays.value : undefined,
      path_length: ca_type.value === 'self_signed' ? pathLength.value : undefined,
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
.container {
  background-color: #ffffff !important; /* Force white background for setup page */
}

.card {
  max-width: 750px;
  width: 100%;
  padding: var(--spacing-xl) !important;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
}

.form-label {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  font-size: 14px;
}

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
  padding: 8px 12px;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-background);
  min-height: 42px;
}

.file-input-text {
  flex: 1;
  color: var(--color-text-secondary);
  font-size: 14px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.validation-step {
  display: flex;
  align-items: center;
  margin-bottom: 4px;
  font-size: 13px;
}

.validation-status-success {
  color: var(--success);
  font-weight: bold;
  margin-right: 8px;
}

.validation-status-error {
  color: var(--danger);
  font-weight: bold;
  margin-right: 8px;
}
</style>
