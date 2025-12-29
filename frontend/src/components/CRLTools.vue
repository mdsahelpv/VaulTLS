About CRL (Certificate Revocation List)
<template>
  <div class="crl-tools">
    <h1>CRL / OCSP Management</h1>
    <hr />

    <!-- OCSP Responder Section -->
    <div class="card mb-4">
      <div class="card-header">
        <h5 class="mb-0">OCSP Responder</h5>
      </div>
      <div class="card-body">
        <div class="row">
          <div class="col-md-6">
            <h6>Status</h6>
            <div class="mb-3">
              <span class="badge" :class="settings?.ocsp?.enabled ? 'bg-success' : 'bg-secondary'">
                {{ settings?.ocsp?.enabled ? 'Active' : 'Disabled' }}
              </span>
            </div>
            <div class="mb-3">
              <h6>OCSP Responder URL</h6>
              <code class="text-break">{{ ocspResponderUrl || 'Not configured - enable OCSP and set server URL' }}</code>
              <small class="text-muted d-block mt-1">
                Endpoint for real-time certificate status checking. Clients can query using OCSP protocol.
                <strong v-if="!settings?.ocsp?.enabled" class="text-warning">⚠️ OCSP is disabled</strong>
              </small>
            </div>
          </div>
          <div class="col-md-6">
            <h6>Response Configuration</h6>
            <dl class="row">
              <dt class="col-sm-6">Validity:</dt>
              <dd class="col-sm-6">{{ settings?.ocsp?.validity_hours || 'N/A' }} hours</dd>
            </dl>
            <div class="mt-3">
              <button
                class="btn btn-outline-info btn-sm"
                @click="testOcsp"
                :disabled="loading"
              >
                <i class="bi bi-check-circle"></i> Check OCSP Config
              </button>
            </div>
          </div>
        </div>

        <div v-if="ocspTestResult" class="alert mt-3" :class="ocspTestResult.success ? 'alert-success' : 'alert-danger'">
          <i class="bi" :class="ocspTestResult.success ? 'bi-check-circle' : 'bi-exclamation-triangle'"></i>
          {{ ocspTestResult.message }}
        </div>
      </div>
    </div>

    <!-- CRL Configuration Section -->
    <div class="card mb-4">
      <div class="card-header">
        <h5 class="mb-0">CRL Configuration</h5>
      </div>
      <div class="card-body">
        <div class="row">
          <div class="col-md-6">
            <h6>Status</h6>
            <div class="mb-3">
              <span class="badge" :class="crlMeta.file_size > 0 ? 'bg-success' : 'bg-secondary'">
                {{ crlMeta.file_size > 0 ? 'Active' : 'No CRLs Generated' }}
              </span>
            </div>
            <div class="mb-3">
              <h6>Distribution URL</h6>
              <code class="text-break">{{ crlDistributionUrl }}</code>
              <small class="text-muted d-block mt-1">
                This URL serves the CRL and can be configured in certificate extensions
              </small>
            </div>
          </div>
          <div class="col-md-6">
            <h6>File Information</h6>
            <dl class="row">
              <dt class="col-sm-5">File Size:</dt>
              <dd class="col-sm-7">{{ formatBytes(crlMeta.file_size) }}</dd>
              <dt class="col-sm-5">Last Modified:</dt>
              <dd class="col-sm-7">{{ formatDate(crlMeta.modified_time) }}</dd>
              <dt class="col-sm-5">Backups:</dt>
              <dd class="col-sm-7">{{ crlMeta.backup_count }}</dd>
            </dl>
          </div>
        </div>

        <div class="d-grid gap-2 d-md-flex">
          <button
            class="btn btn-primary"
            @click="downloadCRLButton"
            :disabled="loading"
          >
            <i class="bi bi-download me-2"></i>
            Download Current CRL
          </button>
          <button
            class="btn btn-info"
            @click="viewCRLDetails"
            :disabled="loading"
          >
            <i class="bi bi-eye me-2"></i>
            View CRL Details
          </button>
          <button
            class="btn btn-warning"
            @click="generateCRLButton"
            :disabled="loading"
          >
            <i class="bi bi-arrow-repeat me-2"></i>
            Generate New CRL
          </button>
          <button
            class="btn btn-outline-secondary"
            @click="loadCRLMetadata"
            :disabled="loading"
          >
            <i class="bi bi-arrow-repeat me-2"></i>
            Refresh
          </button>
        </div>
      </div>
    </div>



    <!-- CRL Settings Section -->
    <div v-if="authStore.isAdmin && settings" class="card mb-4">
      <div class="card-header">
        <h5 class="mb-0">CRL Settings</h5>
      </div>
      <div class="card-body">
        <div class="mb-3 form-check form-switch">
          <input
              type="checkbox"
              class="form-check-input"
              id="crl-enabled"
              v-model="settings.crl.enabled"
              role="switch"
          />
          <label class="form-check-label" for="crl-enabled">
            CRL enabled
          </label>
        </div>
        <div class="mb-3">
          <label for="crl-validity-days" class="form-label">CRL Validity (days)</label>
          <input
              id="crl-validity-days"
              v-model="settings.crl.validity_days"
              type="number"
              class="form-control"
              min="1"
              max="365"
          />
          <div class="form-text">
            How many days the CRL remains valid before requiring regeneration
          </div>
        </div>
        <div class="mb-3">
          <label for="crl-refresh-interval" class="form-label">CRL Refresh Interval (hours)</label>
          <input
              id="crl-refresh-interval"
              v-model="settings.crl.refresh_interval_hours"
              type="number"
              class="form-control"
              min="1"
              max="168"
          />
          <div class="form-text">
            How often the CRL cache is refreshed and regenerated (1 hour - 1 week)
          </div>
        </div>
        <div class="mb-3">
          <label for="crl-distribution-url" class="form-label">CRL Distribution URL (optional)</label>
          <input
              id="crl-distribution-url"
              v-model="settings.crl.distribution_url"
              type="url"
              class="form-control"
              :placeholder="computedCrlUrl || 'https://your-ca.example.com/api/certificates/crl'"
          />
          <div class="form-text">
            Custom URL for CRL distribution. If empty, VaulTLS will use the default URL.
          </div>
        </div>
      </div>
    </div>

    <!-- OCSP Settings Section -->
    <div v-if="authStore.isAdmin && settings" class="card mb-4">
      <div class="card-header">
        <h5 class="mb-0">OCSP Settings</h5>
      </div>
      <div class="card-body">
        <div class="mb-3 form-check form-switch">
          <input
              type="checkbox"
              class="form-check-input"
              id="ocsp-enabled"
              v-model="settings.ocsp.enabled"
              role="switch"
          />
          <label class="form-check-label" for="ocsp-enabled">
            OCSP enabled
          </label>
        </div>
        <div class="mb-3">
          <label for="ocsp-validity-hours" class="form-label">OCSP Response Validity (hours)</label>
          <input
              id="ocsp-validity-hours"
              v-model="settings.ocsp.validity_hours"
              type="number"
              class="form-control"
              min="1"
              max="168"
          />
          <div class="form-text">
            How many hours OCSP responses remain valid
          </div>
        </div>
        <div class="mb-3">
          <label for="ocsp-responder-url" class="form-label">OCSP Responder URL (optional)</label>
          <input
              id="ocsp-responder-url"
              v-model="settings.ocsp.responder_url"
              type="url"
              class="form-control"
              placeholder="https://your-ca.example.com/ocsp"
          />
          <div class="form-text">
            Public URL for OCSP responder (auto-generated if not set)
          </div>
        </div>
      </div>
    </div>



    <!-- Settings Actions -->
    <div v-if="authStore.isAdmin && settings" class="mt-4">
      <div v-if="settingsError" class="alert alert-danger mt-3">
        {{ settingsError }}
      </div>
      <div v-if="settingsSaved" class="alert alert-success mt-3">
        CRL/OCSP Settings saved successfully
      </div>
      <button class="btn btn-primary" @click="saveCrlOcspSettings" :disabled="saving">Save CRL/OCSP Settings</button>
    </div>

    <!-- Error Display -->
    <div v-if="error" class="alert alert-danger mt-3">
      <i class="bi bi-exclamation-triangle me-2"></i>
      {{ error }}
    </div>

    <!-- CRL Details Modal -->
    <div v-if="showCrlDetailsModal" class="modal fade show d-block" tabindex="-1" role="dialog">
      <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">
              <i class="bi bi-info-circle me-2"></i>
              Certificate Revocation List Details
            </h5>
            <button type="button" class="btn-close" @click="closeCrlDetailsModal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <div v-if="crlDetailsLoading" class="text-center">
              <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading CRL details...</span>
              </div>
              <div class="mt-2">Loading CRL details...</div>
            </div>
            <div v-else-if="crlDetails">
              <div class="row">
                <div class="col-md-6">
                  <h6>Basic Information</h6>
                  <dl class="row">
                    <dt class="col-sm-5">CA Name:</dt>
                    <dd class="col-sm-7">{{ crlDetails.ca_name }}</dd>
                    <dt class="col-sm-5">Version:</dt>
                    <dd class="col-sm-7">{{ crlDetails.version }}</dd>
                    <dt class="col-sm-5">File Size:</dt>
                    <dd class="col-sm-7">{{ formatBytes(crlDetails.file_size) }}</dd>
                  </dl>
                </div>
                <div class="col-md-6">
                  <h6>Validity Period</h6>
                  <dl class="row">
                    <dt class="col-sm-5">This Update:</dt>
                    <dd class="col-sm-7">{{ formatDate(crlDetails.this_update) }}</dd>
                    <dt class="col-sm-5">Next Update:</dt>
                    <dd class="col-sm-7">{{ formatDate(crlDetails.next_update) }}</dd>
                  </dl>
                </div>
              </div>

              <div class="row">
                <div class="col-md-6">
                  <h6>Issuer Information</h6>
                  <p class="text-break small">{{ crlDetails.issuer }}</p>
                </div>
                <div class="col-md-6">
                  <h6>Technical Details</h6>
                  <dl class="row">
                    <dt class="col-sm-5">Signature:</dt>
                    <dd class="col-sm-7">{{ crlDetails.signature_algorithm }}</dd>
                    <dt class="col-sm-5">Revoked Certs:</dt>
                    <dd class="col-sm-7">{{ crlDetails.revoked_certificates_count }}</dd>
                  </dl>
                </div>
              </div>
            </div>
            <div v-else-if="crlDetailsError" class="alert alert-danger">
              <i class="bi bi-exclamation-triangle me-2"></i>
              {{ crlDetailsError }}
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeCrlDetailsModal">Close</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal Backdrop -->
    <div v-if="showCrlDetailsModal" class="modal-backdrop fade show" @click="closeCrlDetailsModal"></div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center mt-3">
      <div class="spinner-border" role="status">
        <span class="visually-hidden">Loading...</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { useSetupStore } from '@/stores/setup';
import { downloadCRL, getCrlMetadata, getCrlDetails, fetchCAs, generateCRL } from '@/api/certificates';
import type { CrlMetadata, CrlDetails } from '@/types/Certificate';
import type { CAAndCertificate } from '@/types/CA';

// Props and Emits (if needed for future)
// defineProps()
// defineEmits()

// Stores
const settingsStore = useSettingsStore();
const authStore = useAuthStore();
const setupStore = useSetupStore();

// State
const loading = ref(false);
const error = ref<string | null>(null);
const crlMeta = ref<CrlMetadata>({
  ca_id: 0,
  file_size: 0,
  created_time: 0,
  modified_time: 0,
  backup_count: 0
});
const ocspTestResult = ref<{ success: boolean; message: string } | null>(null);
const settingsError = ref<string | null>(null);
const settingsSaved = ref(false);
const saving = ref(false);

// CRL Details Modal State
const showCrlDetailsModal = ref(false);
const crlDetails = ref<CrlDetails | null>(null);
const crlDetailsLoading = ref(false);
const crlDetailsError = ref<string | null>(null);

// Computed
const settings = computed(() => settingsStore.settings);

// Compute CRL distribution URL
const crlDistributionUrl = computed(() => {
  const baseUrl = settings.value?.common?.vaultls_url;
  return baseUrl ? `${baseUrl.replace(/\/$/, '')}/api/certificates/crl` : '';
});

// Compute CRL URL for placeholder
const computedCrlUrl = computed(() => {
  const baseUrl = settings.value?.common?.vaultls_url;
  return baseUrl ? `${baseUrl.replace(/\/$/, '')}/api/certificates/crl` : '';
});

// Compute OCSP responder URL
// Priority: 1) User-configured OCSP responder URL, 2) Constructed URL from base URL
const ocspResponderUrl = computed(() => {
  // First priority: User-configured OCSP responder URL
  const customOcspUrl = settings.value?.ocsp?.responder_url;
  if (customOcspUrl && customOcspUrl.trim()) {
    return customOcspUrl.trim();
  }

  // Second priority: Constructed URL from base URL + /ocsp
  const baseUrl = settings.value?.common?.vaultls_url;
  return baseUrl ? `${baseUrl.replace(/\/$/, '')}/ocsp` : '';
});

// Methods
const loadCRLMetadata = async () => {
  loading.value = true;
  error.value = null;

  try {
    const meta = await getCrlMetadata();
    crlMeta.value = meta;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load CRL information';
    console.error('CRL metadata error:', err);
  } finally {
    loading.value = false;
  }
};

const downloadCRLButton = async () => {
  try {
    await downloadCRL();
    // Success notification could be added here
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to download CRL';
    console.error('CRL download error:', err);
  }
};

const generateCRLButton = async () => {
  loading.value = true;
  error.value = null;

  try {
    const result = await generateCRL();

    if (result.success) {
      // Reload metadata to show updated CRL info
      await loadCRLMetadata();

      // Show success message
      error.value = null;
      settingsSaved.value = true;
      settingsError.value = null;

      setTimeout(() => {
        settingsSaved.value = false;
      }, 5000);

    } else {
      error.value = result.message || 'Failed to generate CRL';
    }

  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to generate CRL';
    console.error('CRL generation error:', err);
  } finally {
    loading.value = false;
  }
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const formatDate = (timestamp: number): string => {
  return new Date(timestamp).toLocaleString();
};

const testOcsp = async () => {
  loading.value = true;
  ocspTestResult.value = null;

  try {
    // Configuration check - don't try to hit the endpoint since it's behind auth
    const ocspEnabled = settings.value?.ocsp?.enabled;
    const ocspUrl = ocspResponderUrl.value;
    const validityHours = settings.value?.ocsp?.validity_hours || 24;

    console.log('OCSP Configuration Check:');
    console.log('- OCSP enabled:', ocspEnabled);
    console.log('- OCSP URL:', ocspUrl);
    console.log('- Response validity:', validityHours, 'hours');

    if (!ocspEnabled) {
      ocspTestResult.value = {
        success: false,
        message: `❌ OCSP is not enabled.\n\nTo enable OCSP:\n• Go to Settings → OCSP Settings\n• Check "OCSP enabled"\n• Set response validity hours\n• Save the settings\n\nOCSP allows real-time certificate status checking.`
      };
      return;
    }

    if (!ocspUrl || ocspUrl.trim() === '' || ocspUrl === '/ocsp') {
      ocspTestResult.value = {
        success: false,
        message: `❌ OCSP URL is not configured.\n\nCurrent URL: ${ocspUrl}\n\nTo fix:\n• Set VaultLS URL in Common Settings, OR\n• Set custom OCSP Responder URL in OCSP Settings`
      };
      return;
    }

    // OCSP is configured and enabled
    ocspTestResult.value = {
      success: true,
      message: `✅ OCSP is properly configured!\n\n📍 OCSP Responder URL: ${ocspUrl}\n⏰ Response validity: ${validityHours} hours\n🔐 OCSP endpoints require authentication\n\n📋 To test OCSP with real clients:\n\ncurl -X POST "${ocspUrl}" \\\n  -H "Authorization: Bearer <token>" \\\n  -H "Content-Type: application/ocsp-request" \\\n  -d @ocsp-request.der\n\nopenssl ocsp -issuer ca.pem -cert cert.pem \\\n  -url "${ocspUrl}" \\\n  -header "Authorization" "Bearer <token>"`
    };

  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Unknown error';
    console.error('OCSP config check error:', err);

    ocspTestResult.value = {
      success: false,
      message: `❌ Error checking OCSP configuration: ${errorMessage}`
    };
  } finally {
    loading.value = false;
  }
};

const saveCrlOcspSettings = async () => {
  settingsError.value = null;
  settingsSaved.value = false;
  saving.value = true;

  try {
    const success = await settingsStore.saveSettings();
    if (success) {
      settingsSaved.value = true;
      // Reload setup store to reflect any changes
      await setupStore.reload();
    }
  } catch (err) {
    settingsError.value = err instanceof Error ? err.message : 'Failed to save CRL/OCSP settings';
    console.error('Settings save error:', err);
  } finally {
    saving.value = false;
  }
};

const viewCRLDetails = async () => {
  showCrlDetailsModal.value = true;
  crlDetailsLoading.value = true;
  crlDetailsError.value = null;
  crlDetails.value = null;

  try {
    const details = await getCrlDetails();
    crlDetails.value = details;
  } catch (err) {
    crlDetailsError.value = err instanceof Error ? err.message : 'Failed to load CRL details';
    console.error('CRL details error:', err);
  } finally {
    crlDetailsLoading.value = false;
  }
};

const closeCrlDetailsModal = () => {
  showCrlDetailsModal.value = false;
  crlDetails.value = null;
  crlDetailsError.value = null;
};

// Lifecycle
onMounted(async () => {
  await loadCRLMetadata();
  // Fetch settings for admin users
  if (authStore.isAdmin) {
    await settingsStore.fetchSettings();
  }
});
</script>

<style scoped>
.crl-tools {
  background-color: transparent;
}

.crl-tools ::v-deep(.alert-success) {
  white-space: pre-line;
}

@media (max-width: 768px) {
  .crl-tools {
    padding: 0;
  }
}
</style>
