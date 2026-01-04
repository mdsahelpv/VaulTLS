<template>
  <div
    v-if="modelValue"
    class="modal show d-block"
    tabindex="-1"
    style="background: rgba(0, 0, 0, 0.5)"
  >
    <div class="modal-dialog modal-xl">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Generate New Certificate</h5>
          <button type="button" class="btn-close" @click="closeModal"></button>
        </div>
        <div class="modal-body">
          <div class="mb-3">
            <label for="certName" class="form-label">Common Name</label>
            <input
              id="certName"
              v-model="certReq.cert_name"
              type="text"
              class="form-control"
              placeholder="Enter certificate name"
            />
          </div>
          <div class="mb-3">
            <label for="certType" class="form-label">Certificate Type</label>
            <select
              class="form-select"
              id="certType"
              v-model="certReq.cert_type"
              required
            >
              <option v-if="!isRootCa" :value="CertificateType.Client">Client</option>
              <option v-if="!isRootCa" :value="CertificateType.Server">Server</option>
              <option v-if="isRootCa" :value="CertificateType.SubordinateCA">Subordinate CA</option>
            </select>
            <div v-if="isRootCa" class="form-text text-info">
              <i class="bi bi-info-circle me-1"></i>
              Root CA Server mode: Only subordinate CA certificates can be issued.
            </div>
          </div>
          <div class="mb-3">
            <label for="caId" class="form-label">Certificate Authority (CA)</label>
            <select
              id="caId"
              v-model="certReq.ca_id"
              class="form-control"
            >
              <option value="" disabled>Select a CA</option>
              <option v-for="ca in availableCas" :key="ca.id" :value="ca.id">
                {{ ca.name }} ({{ ca.is_self_signed ? 'Self-Signed' : 'Imported' }})
              </option>
            </select>
            <div class="form-text">
              Choose which CA to use for signing this certificate.
            </div>
          </div>

          <!-- Advanced Certificate Configuration (Collapsible) -->
          <div class="mb-3">
            <button
              class="btn btn-outline-secondary btn-sm"
              type="button"
              @click="advancedConfigExpanded = !advancedConfigExpanded"
            >
              <i class="bi" :class="advancedConfigExpanded ? 'bi-chevron-up' : 'bi-chevron-down'"></i>
              Advanced Configuration
            </button>
          </div>

          <!-- Advanced Configuration Panel -->
          <div v-if="advancedConfigExpanded" class="border rounded p-3 mb-3 bg-light">
            <h6 class="mb-3">Advanced Certificate Configuration</h6>

            <!-- Cryptographic Parameters -->
            <div class="row mb-3">
              <div class="col-md-4">
                <label for="keyType" class="form-label">Key Type</label>
                <select
                  id="keyType"
                  v-model="certReq.key_type"
                  class="form-select"
                >
                  <option value="rsa">RSA</option>
                  <option value="ecdsa">ECDSA</option>
                </select>
              </div>
              <div class="col-md-4">
                <label for="keySize" class="form-label">Key Size</label>
                <select
                  id="keySize"
                  v-model="certReq.key_size"
                  class="form-select"
                >
                  <option v-if="certReq.key_type === 'rsa'" value="2048">2048 bits</option>
                  <option v-if="certReq.key_type === 'rsa'" value="3072">3072 bits</option>
                  <option v-if="certReq.key_type === 'rsa'" value="4096">4096 bits</option>
                  <option v-if="certReq.key_type === 'ecdsa'" value="256">P-256</option>
                  <option v-if="certReq.key_type === 'ecdsa'" value="384">P-384</option>
                </select>
              </div>
              <div class="col-md-4">
                <label for="hashAlgorithm" class="form-label">Hash Algorithm</label>
                <select
                  id="hashAlgorithm"
                  v-model="certReq.hash_algorithm"
                  class="form-select"
                >
                  <option value="sha256">SHA-256</option>
                  <option value="sha384">SHA-384</option>
                  <option value="sha512">SHA-512</option>
                </select>
              </div>
            </div>

            <!-- Certificate URLs -->
            <div class="mb-3">
              <h6 class="mb-2">Certificate URLs</h6>
              <div class="row">
                <div class="col-md-4">
                  <label for="aiaUrl" class="form-label">Authority Information Access (AIA)</label>
                  <input
                    id="aiaUrl"
                    v-model="certReq.aia_url"
                    type="url"
                    class="form-control"
                    :placeholder="`${getCurrentBaseUrl()}/api/certificates/ca/download`"
                  />
                  <div class="form-text text-muted">URL where CA certificates can be downloaded</div>
                </div>
                <div class="col-md-4">
                  <label for="ocspUrl" class="form-label">OCSP Responder URL</label>
                  <input
                    id="ocspUrl"
                    v-model="certReq.ocsp_url"
                    type="url"
                    class="form-control"
                    :placeholder="`${getCurrentBaseUrl()}/api/certificates/ocsp`"
                  />
                  <div class="form-text text-muted">URL for real-time certificate status checking</div>
                </div>
                <div class="col-md-4">
                  <label for="cdpUrl" class="form-label">CRL Distribution Point (CDP)</label>
                  <input
                    id="cdpUrl"
                    v-model="certReq.cdp_url"
                    type="url"
                    class="form-control"
                    :placeholder="`${getCurrentBaseUrl()}/api/certificates/crl`"
                  />
                  <div class="form-text text-muted">URL where Certificate Revocation List can be downloaded</div>
                </div>
              </div>
            </div>

            <!-- DNS Names (for server certificates) -->
            <div class="mb-3" v-if="certReq.cert_type === CertificateType.Server">
              <label class="form-label">
                DNS Names
                <span class="text-danger">*</span>
                <small class="text-muted">(required for server certificates)</small>
              </label>
              <div v-for="(_, index) in certReq.dns_names" :key="index" class="mb-2">
                <div class="input-group">
                  <input
                    type="text"
                    class="form-control"
                    :class="{ 'is-invalid': certReq.cert_type === CertificateType.Server && !hasValidDNSNames }"
                    v-model="certReq.dns_names[index]"
                    :placeholder="'DNS Name ' + (index + 1)"
                  />
                  <button
                    v-if="index === certReq.dns_names.length - 1"
                    type="button"
                    class="btn btn-outline-secondary"
                    @click="addDNSField"
                  >
                    +
                  </button>
                  <button
                    v-if="certReq.dns_names.length > 1"
                    type="button"
                    class="btn btn-outline-danger"
                    @click="removeDNSField(index)"
                  >
                    −
                  </button>
                </div>
              </div>
              <div v-if="certReq.cert_type === CertificateType.Server && !hasValidDNSNames" class="invalid-feedback d-block">
                At least one DNS name is required for server certificates.
              </div>
            </div>
          </div>

          <!-- Certificate Validity -->
          <div class="mb-3">
            <label for="validityYears" class="form-label">Certificate Validity (Years)</label>
            <input
              id="validityYears"
              v-model.number="certReq.validity_in_years"
              type="number"
              class="form-control"
              min="1"
              max="10"
              placeholder="1"
            />
            <div class="form-text">
              Number of years the certificate will be valid (default: 1 year).
            </div>
          </div>

          <!-- Certificate Password -->
          <div v-if="!isSystemPasswordRule(passwordRule)" class="mb-3">
            <label for="certPassword" class="form-label">Certificate Password</label>
            <div class="input-group">
              <input
                id="certPassword"
                v-model="certReq.pkcs12_password"
                :type="showPassword ? 'text' : 'password'"
                class="form-control"
                :placeholder="certReq.system_generated_password ? 'Will be generated automatically' : 'Enter password'"
                :disabled="certReq.system_generated_password"
                :required="passwordRule === PasswordRule.Required"
              />
              <button
                class="btn btn-outline-secondary"
                type="button"
                @click="showPassword = !showPassword"
              >
                <i class="bi" :class="showPassword ? 'bi-eye-slash' : 'bi-eye'"></i>
              </button>
            </div>
            <div class="form-check form-switch mt-2">
              <input
                type="checkbox"
                class="form-check-input"
                id="systemGeneratedPassword"
                v-model="certReq.system_generated_password"
                role="switch"
                :disabled="isSystemPasswordRule(passwordRule)"
              />
              <label class="form-check-label" for="systemGeneratedPassword">
                System Generated Password
              </label>
            </div>
          </div>

          <!-- User Assignment -->
          <div class="mb-3">
            <label for="userId" class="form-label">Assign to User</label>
            <select
              id="userId"
              v-model.number="certReq.user_id"
              class="form-control"
            >
              <option value="0" disabled>Select a user</option>
              <option v-for="user in users" :key="user.id" :value="user.id">
                {{ user.name }} ({{ user.email }})
              </option>
            </select>
            <div class="form-text">
              Choose which user will own this certificate.
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" @click="closeModal">Cancel</button>
          <button
            type="button"
            class="btn btn-primary"
            @click="generateCertificate"
            :disabled="!canGenerateCertificate"
          >
            <i class="bi bi-plus-circle me-1"></i>
            Generate Certificate
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { CertificateType, CertificateRenewMethod } from '@/types/Certificate';
import { PasswordRule } from '@/types/Settings';
import type { CertificateRequirements } from '@/types/CertificateRequirements';
import type { CAAndCertificate } from '@/types/CA';
import type { User } from '@/types/User';

// Helper function to check if password rule is system
const isSystemPasswordRule = (rule: PasswordRule): boolean => {
  return rule === PasswordRule.System;
};

interface Props {
  modelValue: boolean;
  isRootCa: boolean;
  availableCas: CAAndCertificate[];
  users: User[];
  passwordRule: PasswordRule;
}

interface Emits {
  (e: 'update:modelValue', value: boolean): void;
  (e: 'certificate-created'): void;
}

defineProps<Props>();
const emit = defineEmits<Emits>();

// Reactive data
const certReq = ref<CertificateRequirements>({
  cert_name: '',
  user_id: 0,
  validity_in_years: 1,
  system_generated_password: true,
  pkcs12_password: '',
  notify_user: false,
  cert_type: CertificateType.Client,
  dns_names: [''],
  renew_method: CertificateRenewMethod.None,
  ca_id: undefined,
  key_type: 'rsa',
  key_size: '4096',
  hash_algorithm: 'sha256',
  aia_url: '',
  ocsp_url: '',
  cdp_url: '',
});

const showPassword = ref(false);
const advancedConfigExpanded = ref(false);

// Computed properties
const canGenerateCertificate = computed(() => {
  return certReq.value.cert_name.trim() &&
         certReq.value.cert_type &&
         certReq.value.ca_id &&
         certReq.value.validity_in_years > 0 &&
         (certReq.value.cert_type !== CertificateType.Server || hasValidDNSNames.value);
});

const hasValidDNSNames = computed(() => {
  if (certReq.value.cert_type !== CertificateType.Server) {
    return true;
  }
  return certReq.value.dns_names.some(dns => dns.trim().length > 0);
});

// Methods
const closeModal = () => {
  emit('update:modelValue', false);
  resetForm();
};

const resetForm = () => {
  certReq.value = {
    cert_name: '',
    user_id: 0,
    validity_in_years: 1,
    system_generated_password: true,
    pkcs12_password: '',
    notify_user: false,
    cert_type: CertificateType.Client,
    dns_names: [''],
    renew_method: CertificateRenewMethod.None,
    ca_id: undefined,
    key_type: 'rsa',
    key_size: '4096',
    hash_algorithm: 'sha256',
    aia_url: '',
    ocsp_url: '',
    cdp_url: '',
  };
  showPassword.value = false;
  advancedConfigExpanded.value = false;
};

const addDNSField = () => {
  certReq.value.dns_names.push('');
};

const removeDNSField = (index: number) => {
  if (certReq.value.dns_names.length > 1) {
    certReq.value.dns_names.splice(index, 1);
  }
};

const generateCertificate = async () => {
  try {
    // Import the certificate store
    const { useCertificateStore } = await import('@/stores/certificates');
    const certificateStore = useCertificateStore();

    await certificateStore.createCertificate(certReq.value);
    emit('certificate-created');
    closeModal();
  } catch (error) {
    console.error('Failed to generate certificate:', error);
    // TODO: Show error message to user
  }
};

// Function to get current base URL
const getCurrentBaseUrl = () => {
  const origin = window.location.origin;
  return origin || 'http://localhost:8000';
};

// Watch for key type changes to update key size options
watch(() => certReq.value.key_type, (newKeyType) => {
  if (newKeyType === 'rsa' && certReq.value.key_size && ['256', '384'].includes(certReq.value.key_size)) {
    certReq.value.key_size = '4096';
  } else if (newKeyType === 'ecdsa' && certReq.value.key_size && ['2048', '3072', '4096'].includes(certReq.value.key_size)) {
    certReq.value.key_size = '256';
  }
});
</script>

<style scoped>
.modal-xl {
  max-width: 1200px;
}

.badge {
  font-size: 0.75rem;
}

.btn-close {
  margin: 0;
}
</style>
