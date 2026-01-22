<template>
  <div class="ca-tools-container">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2 class="mb-0">
        Certificate Authority Details
      </h2>
      <button
        class="btn btn-outline-primary"
        :disabled="loading"
        @click="downloadCA"
      >
        <i class="bi bi-download me-2" />
        Download CA Certificate
      </button>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading"
      class="text-center py-5"
    >
      <div
        class="spinner-border text-primary"
        role="status"
      >
        <span class="visually-hidden">Loading...</span>
      </div>
      <p class="mt-3 text-muted">
        Loading CA details...
      </p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error"
      class="alert alert-danger"
    >
      <i class="bi bi-exclamation-triangle me-2" />
      {{ error }}
    </div>

    <!-- CA Details -->
    <div
      v-else-if="caDetails"
      class="row"
    >
      <!-- Basic Information -->
      <div class="col-lg-6 mb-4">
        <div class="card h-100">
          <div class="card-header">
            <h5 class="mb-0">
              <i class="bi bi-info-circle me-2" />
              Basic Information
            </h5>
          </div>
          <div class="card-body">
            <div class="row">
              <div class="col-sm-4">
                <strong>Name:</strong>
              </div>
              <div class="col-sm-8">
                {{ caDetails.name }}
              </div>
            </div>
            <hr>
            <div class="row">
              <div class="col-sm-4">
                <strong>Serial Number:</strong>
              </div>
              <div class="col-sm-8">
                <code>{{ caDetails.serial_number }}</code>
              </div>
            </div>
            <hr>
            <div class="row">
              <div class="col-sm-4">
                <strong>Key Size:</strong>
              </div>
              <div class="col-sm-8">
                {{ caDetails.key_size }}
              </div>
            </div>
            <hr>
            <div class="row">
              <div class="col-sm-4">
                <strong>Signature Algorithm:</strong>
              </div>
              <div class="col-sm-8">
                {{ caDetails.signature_algorithm }}
              </div>
            </div>
            <hr>
            <div class="row">
              <div class="col-sm-4">
                <strong>Type:</strong>
              </div>
              <div class="col-sm-8">
                <span
                  class="badge"
                  :class="caDetails.is_self_signed ? 'bg-success' : 'bg-warning'"
                >
                  {{ caDetails.is_self_signed ? 'Self-Signed' : 'Imported' }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Validity Information -->
      <div class="col-lg-6 mb-4">
        <div class="card h-100">
          <div class="card-header">
            <h5 class="mb-0">
              <i class="bi bi-calendar-check me-2" />
              Validity Period
            </h5>
          </div>
          <div class="card-body">
            <div class="row">
              <div class="col-sm-4">
                <strong>Created:</strong>
              </div>
              <div class="col-sm-8">
                {{ formatDate(caDetails.created_on) }}
              </div>
            </div>
            <hr>
            <div class="row">
              <div class="col-sm-4">
                <strong>Expires:</strong>
              </div>
              <div class="col-sm-8">
                {{ formatDate(caDetails.valid_until) }}
              </div>
            </div>
            <hr>
            <div class="row">
              <div class="col-sm-4">
                <strong>Status:</strong>
              </div>
              <div class="col-sm-8">
                <span
                  class="badge"
                  :class="getValidityStatusClass()"
                >
                  {{ getValidityStatus() }}
                </span>
              </div>
            </div>
            <hr>
            <div class="row">
              <div class="col-sm-4">
                <strong>Days Remaining:</strong>
              </div>
              <div class="col-sm-8">
                {{ getDaysRemaining() }}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Subject Information -->
      <div class="col-lg-6 mb-4">
        <div class="card h-100">
          <div class="card-header">
            <h5 class="mb-0">
              <i class="bi bi-person me-2" />
              Subject
            </h5>
          </div>
          <div class="card-body">
            <pre class="mb-0 text-break">{{ caDetails.subject }}</pre>
          </div>
        </div>
      </div>

      <!-- Issuer Information -->
      <div class="col-lg-6 mb-4">
        <div class="card h-100">
          <div class="card-header">
            <h5 class="mb-0">
              <i class="bi bi-building me-2" />
              Issuer
            </h5>
          </div>
          <div class="card-body">
            <pre class="mb-0 text-break">{{ caDetails.issuer }}</pre>
          </div>
        </div>
      </div>

      <!-- Certificate PEM -->
      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0">
              <i class="bi bi-file-earmark-text me-2" />
              Certificate (PEM Format)
            </h5>
            <button
              class="btn btn-sm btn-outline-secondary"
              :disabled="copying"
              @click="copyToClipboard"
            >
              <i
                class="bi"
                :class="copying ? 'bi-check' : 'bi-clipboard'"
              />
              {{ copying ? 'Copied!' : 'Copy' }}
            </button>
          </div>
          <div class="card-body">
            <pre class="certificate-pem mb-0">{{ caDetails.certificate_pem }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- No CA Found -->
    <div
      v-else
      class="text-center py-5"
    >
      <i
        class="bi bi-exclamation-triangle text-warning"
        style="font-size: 3rem;"
      />
      <h4 class="mt-3">
        No Certificate Authority Found
      </h4>
      <p class="text-muted">
        The application hasn't been set up with a CA yet.
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useCAStore } from '@/stores/ca';

const caStore = useCAStore();

// Use computed properties to react to store changes
const caDetails = computed(() => caStore.currentCADetails);
const loading = computed(() => caStore.loading);
const error = computed(() => caStore.error);
const copying = ref(false);

const loadCADetails = async () => {
  try {
    await caStore.fetchCADetails();
  } catch (err: unknown) {
    console.error('Failed to load CA details:', err);
    // Error is already handled by the store
  }
};

const downloadCA = async () => {
  try {
    await caStore.downloadCACertificate();
  } catch (err: unknown) {
    console.error('Failed to download CA certificate:', err);
    alert('Failed to download CA certificate');
  }
};

const copyToClipboard = async () => {
  if (!caDetails.value) return;

  try {
    await navigator.clipboard.writeText(caDetails.value.certificate_pem);
    copying.value = true;
    setTimeout(() => {
      copying.value = false;
    }, 2000);
  } catch (err) {
    console.error('Failed to copy to clipboard:', err);
    // Fallback for older browsers
    const textArea = document.createElement('textarea');
    textArea.value = caDetails.value.certificate_pem;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand('copy');
    document.body.removeChild(textArea);
    copying.value = true;
    setTimeout(() => {
      copying.value = false;
    }, 2000);
  }
};

const formatDate = (timestamp: number): string => {
  return new Date(timestamp).toLocaleString();
};

const getValidityStatus = (): string => {
  if (!caDetails.value) return 'Unknown';

  const now = Date.now();
  const validUntil = caDetails.value.valid_until;

  if (validUntil < now) {
    return 'Expired';
  } else if (validUntil < now + (30 * 24 * 60 * 60 * 1000)) { // 30 days
    return 'Expiring Soon';
  } else {
    return 'Valid';
  }
};

const getValidityStatusClass = (): string => {
  const status = getValidityStatus();
  switch (status) {
    case 'Expired':
      return 'bg-danger';
    case 'Expiring Soon':
      return 'bg-warning text-dark';
    case 'Valid':
      return 'bg-success';
    default:
      return 'bg-secondary';
  }
};

const getDaysRemaining = (): string => {
  if (!caDetails.value) return 'Unknown';

  const now = Date.now();
  const validUntil = caDetails.value.valid_until;
  const diff = validUntil - now;

  if (diff < 0) {
    return 'Expired';
  }

  const days = Math.floor(diff / (24 * 60 * 60 * 1000));
  if (days === 0) {
    const hours = Math.floor(diff / (60 * 60 * 1000));
    return `${hours} hours`;
  }

  return `${days} days`;
};

onMounted(() => {
  loadCADetails();
});
</script>

<style scoped>
.ca-details-container {
  padding: 20px;
}

.card {
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  border: 1px solid #e9ecef;
}

.card-header {
  background-color: #f8f9fa;
  border-bottom: 1px solid #e9ecef;
}

.certificate-pem {
  background-color: #f8f9fa;
  padding: 15px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  line-height: 1.4;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 400px;
  overflow-y: auto;
}

.btn-outline-secondary:hover {
  background-color: #6c757d;
  border-color: #6c757d;
}

.badge {
  font-size: 0.75rem;
}

@media (max-width: 768px) {
  .ca-details-container {
    padding: 10px;
  }

  .card-body {
    padding: 1rem;
  }
}
</style>
