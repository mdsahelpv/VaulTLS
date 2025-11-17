<template>
  <div class="crl-tools">
    <h1>CRL Management</h1>
    <hr />

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
              <span class="badge" :class="crlMeta.backup_count > 0 ? 'bg-success' : 'bg-secondary'">
                {{ crlMeta.backup_count > 0 ? 'Active' : 'No CRLs Generated' }}
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

    <!-- CRL Backup Files Section -->
    <div class="card mb-4" v-if="crlFiles.length > 0">
      <div class="card-header">
        <h5 class="mb-0">CRL Backup Files</h5>
      </div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="table table-striped">
            <thead>
              <tr>
                <th>Filename</th>
                <th>CA ID</th>
                <th>Created</th>
                <th>Size</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="file in crlFiles" :key="file.filename">
                <td>{{ file.filename }}</td>
                <td>{{ file.ca_id }}</td>
                <td>{{ formatDate(file.created_time) }}</td>
                <td>{{ formatBytes(file.file_size) }}</td>
                <td>
                  <button
                    class="btn btn-sm btn-outline-primary me-2"
                    @click="downloadBackupFile(file.filename)"
                    :disabled="loading"
                  >
                    <i class="bi bi-download"></i>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Information Section -->
    <div class="card">
      <div class="card-header">
        <h5 class="mb-0">About CRL (Certificate Revocation List)</h5>
      </div>
      <div class="card-body">
        <div class="row">
          <div class="col-md-6">
            <h6>What is a CRL?</h6>
            <p class="text-muted">
              A Certificate Revocation List (CRL) is a list of certificates that have been revoked before their scheduled expiration date.
              When a certificate is compromised, lost, or no longer trusted, it should be revoked and added to the CRL.
            </p>

            <h6>CRL Format</h6>
            <p class="text-muted">
              CRLs are distributed in DER or PEM format and are signed by the Certificate Authority (CA) that issued the certificates.
            </p>

            <h6>CRL Usage</h6>
            <p class="text-muted">
              Applications and systems using certificates can download and check CRLs to verify if certificates are still valid.
            </p>
          </div>
          <div class="col-md-6">
            <h6>Current CRL Settings</h6>
            <dl class="row" v-if="settings?.crl">
              <dt class="col-sm-6">Enabled:</dt>
              <dd class="col-sm-6">
                <i class="bi" :class="settings.crl.enabled ? 'bi-check-circle text-success' : 'bi-x-circle text-danger'"></i>
                {{ settings.crl.enabled ? 'Yes' : 'No' }}
              </dd>
              <dt class="col-sm-6">Validity:</dt>
              <dd class="col-sm-6">{{ settings.crl.validity_days }} days</dd>
              <dt class="col-sm-6">Refresh Interval:</dt>
              <dd class="col-sm-6">{{ settings.crl.refresh_interval_hours }} hours</dd>
              <dt class="col-sm-6">Distribution URL:</dt>
              <dd class="col-sm-6">
                <span v-if="settings.crl.distribution_url">{{ settings.crl.distribution_url }}</span>
                <span v-else class="text-muted">Not configured</span>
              </dd>
            </dl>

            <div class="alert alert-info mt-3" v-if="!settings?.crl?.enabled">
              <i class="bi bi-info-circle me-2"></i>
              CRL is currently disabled. Configure it in Settings → CRL section.
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Error Display -->
    <div v-if="error" class="alert alert-danger mt-3">
      <i class="bi bi-exclamation-triangle me-2"></i>
      {{ error }}
    </div>

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
import { downloadCRL, getCrlMetadata, listCrlFiles, downloadCrlBackup } from '@/api/certificates';
import type { CrlMetadata, CrlFileInfo } from '@/types/Certificate';

// Props and Emits (if needed for future)
// defineProps()
// defineEmits()

// Stores
const settingsStore = useSettingsStore();
const authStore = useAuthStore();

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
const crlFiles = ref<CrlFileInfo[]>([]);

// Computed
const settings = computed(() => settingsStore.settings);

// Compute CRL distribution URL
const crlDistributionUrl = computed(() => {
  const baseUrl = settings.value?.common?.vaultls_url;
  return baseUrl ? `${baseUrl.replace(/\/$/, '')}/api/certificates/crl` : '';
});

// Methods
const loadCRLMetadata = async () => {
  loading.value = true;
  error.value = null;

  try {
    const meta = await getCrlMetadata();
    crlMeta.value = meta;

    // Also load CRL files if admin
    if (authStore.isAdmin) {
      const files = await listCrlFiles();
      crlFiles.value = files;
    }
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

const downloadBackupFile = async (filename: string) => {
  try {
    await downloadCrlBackup(filename);
    // Success notification could be added here
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to download CRL backup';
    console.error('CRL backup download error:', err);
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

// Lifecycle
onMounted(async () => {
  await loadCRLMetadata();
});
</script>

<style scoped>
.crl-tools {
  padding: var(--spacing-xl);
  background-color: var(--color-page-background);
  color: var(--color-text-primary);
  min-height: 100vh;
}

/* Dark mode support */
[data-theme="dark"] .crl-tools ::v-deep(.card) {
  background-color: var(--color-card);
  border-color: rgba(255, 255, 255, 0.1);
  color: var(--color-text-primary);
}

[data-theme="dark"] .crl-tools ::v-deep(.card-header) {
  background-color: var(--color-hover);
  border-bottom-color: rgba(255, 255, 255, 0.1);
  color: var(--color-text-primary);
}

[data-theme="dark"] .crl-tools ::v-deep(.table) {
  color: var(--color-text-primary);
}

[data-theme="dark"] .crl-tools ::v-deep(.table-striped tbody tr:nth-of-type(odd)) {
  background-color: var(--color-hover);
}

/* Spinner styling */
.spinner-border {
  width: 1rem;
  height: 1rem;
}

/* Alert styling */
[data-theme="dark"] .crl-tools ::v-deep(.alert-danger) {
  background-color: rgba(220, 53, 69, 0.1);
  border-color: rgba(220, 53, 69, 0.2);
  color: #ea868f;
}

[data-theme="dark"] .crl-tools ::v-deep(.alert-info) {
  background-color: rgba(66, 133, 244, 0.1);
  border-color: rgba(66, 133, 244, 0.2);
  color: var(--color-text-primary);
}
</style>
