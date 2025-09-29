<template>
  <div class="ca-tools-container">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2 class="mb-0">CA Tools</h2>
      <button
        class="btn btn-primary"
        @click="showAddCAModal = true"
      >
        <i class="bi bi-plus-circle me-2"></i>
        Add CA
      </button>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status">
        <span class="visually-hidden">Loading...</span>
      </div>
      <p class="mt-3 text-muted">Loading CAs...</p>
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="alert alert-danger">
      <i class="bi bi-exclamation-triangle me-2"></i>
      {{ error }}
      <button class="btn btn-sm btn-outline-danger ms-3" @click="loadCAs">Retry</button>
    </div>

    <!-- CA List -->
    <div v-else-if="cas && cas.length > 0" class="card">
      <div class="card-header">
        <h5 class="mb-0">
          <i class="bi bi-shield-check me-2"></i>
          Certificate Authorities ({{ cas.length }})
        </h5>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover mb-0">
            <thead class="table-light">
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th>Created</th>
                <th>Expires</th>
                <th class="text-center">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="ca in cas"
                :key="ca.id"
                :class="{ 'table-active': selectedCA?.id === ca.id }"
                @click="selectedCA = selectedCA?.id === ca.id ? null : ca"
              >
                <td>
                  <strong>{{ ca.name }}</strong>
                  <br>
                  <small class="text-muted">{{ ca.serial_number }}</small>
                </td>
                <td>
                  <span class="badge" :class="ca.is_self_signed ? 'bg-success' : 'bg-info'">
                    {{ ca.is_self_signed ? 'Self-Signed' : 'Imported' }}
                  </span>
                </td>
                <td>
                  <span class="badge" :class="getStatusClass(ca)">
                    {{ getStatusText(ca) }}
                  </span>
                </td>
                <td>{{ formatDate(ca.created_on) }}</td>
                <td>{{ formatDate(ca.valid_until) }}</td>
                <td>
                  <div class="d-flex flex-sm-row flex-column gap-1">
                    <button
                      class="btn btn-primary btn-sm"
                      @click="viewCADetails(ca)"
                      title="View CA Details"
                    >
                      <i class="bi bi-eye"></i> View
                    </button>
                    <button
                      class="btn btn-primary btn-sm flex-grow-1"
                      @click="handleDownloadCA(ca)"
                      title="Download CA Certificate"
                    >
                      Download
                    </button>
                    <button
                      v-if="isAdmin"
                      class="btn btn-danger btn-sm flex-grow-1"
                      @click="confirmDeleteCA(ca)"
                      title="Delete CA"
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- No CAs Found -->
    <div v-else class="text-center py-5">
      <i class="bi bi-shield-slash text-muted" style="font-size: 3rem;"></i>
      <h4 class="mt-3">No Certificate Authorities Found</h4>
      <p class="text-muted">Create your first CA to start managing certificates.</p>
      <button class="btn btn-primary" @click="showAddCAModal = true">
        <i class="bi bi-plus-circle me-2"></i>
        Create Your First CA
      </button>
    </div>

    <!-- Add CA Modal -->
    <div class="modal fade" :class="{ show: showAddCAModal }" :style="{ display: showAddCAModal ? 'block' : 'none' }" tabindex="-1">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Add Certificate Authority</h5>
            <button type="button" class="btn-close" @click="showAddCAModal = false"></button>
          </div>
          <div class="modal-body">
            <div class="row">
              <div class="col-md-6">
                <div class="card h-100" :class="{ 'border-primary': caCreationType === 'self-signed' }">
                  <div class="card-body text-center">
                    <i class="bi bi-key text-primary" style="font-size: 3rem;"></i>
                    <h5 class="mt-3">Self-Signed CA</h5>
                    <p class="text-muted">Generate a new Certificate Authority for your organization.</p>
                    <button
                      class="btn btn-outline-primary"
                      :class="{ 'btn-primary': caCreationType === 'self-signed' }"
                      @click="caCreationType = 'self-signed'"
                    >
                      Select
                    </button>
                  </div>
                </div>
              </div>
              <div class="col-md-6">
                <div class="card h-100" :class="{ 'border-primary': caCreationType === 'import' }">
                  <div class="card-body text-center">
                    <i class="bi bi-upload text-success" style="font-size: 3rem;"></i>
                    <h5 class="mt-3">Import CA Chain</h5>
                    <p class="text-muted">Import an existing Certificate Authority from PKCS#12 file.</p>
                    <button
                      class="btn btn-outline-success"
                      :class="{ 'btn-success': caCreationType === 'import' }"
                      @click="caCreationType = 'import'"
                    >
                      Select
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <!-- Self-Signed CA Form -->
            <div v-if="caCreationType === 'self-signed'" class="mt-4">
              <form @submit.prevent="createSelfSignedCAWrapper">
                <div class="mb-3">
                  <label for="caName" class="form-label">CA Name</label>
                  <input
                    type="text"
                    class="form-control"
                    id="caName"
                    v-model="selfSignedForm.name"
                    required
                    placeholder="e.g., MyCompany CA"
                  >
                </div>
                <div class="mb-3">
                  <label for="caValidity" class="form-label">Validity (Years)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="caValidity"
                    v-model.number="selfSignedForm.validityYears"
                    required
                    min="1"
                    max="30"
                  >
                </div>
                <div class="mb-3">
                  <label for="caPassword" class="form-label">CA Private Key Password (Optional)</label>
                  <input
                    type="password"
                    class="form-control"
                    id="caPassword"
                    v-model="selfSignedForm.password"
                    placeholder="Leave empty for system-generated password"
                  >
                </div>
                <div class="d-flex gap-2">
                  <button
                    type="submit"
                    class="btn btn-primary"
                    :disabled="creatingCA"
                  >
                    <span v-if="creatingCA" class="spinner-border spinner-border-sm me-2" role="status"></span>
                    Create CA
                  </button>
                  <button type="button" class="btn btn-secondary" @click="showAddCAModal = false">Cancel</button>
                </div>
              </form>
            </div>

            <!-- Import CA Form -->
            <div v-if="caCreationType === 'import'" class="mt-4">
              <form @submit.prevent="importCA">
                <div class="mb-3">
                  <label for="pkcs12File" class="form-label">PKCS#12 File (.p12/.pfx)</label>
                  <input
                    type="file"
                    class="form-control"
                    id="pkcs12File"
                    ref="fileInput"
                    @change="handleFileSelect"
                    accept=".p12,.pfx"
                    required
                  >
                </div>
                <div class="mb-3">
                  <label for="importPassword" class="form-label">PKCS#12 Password</label>
                  <input
                    type="password"
                    class="form-control"
                    id="importPassword"
                    v-model="importForm.password"
                    required
                  >
                </div>
                <div class="alert alert-info">
                  <i class="bi bi-info-circle me-2"></i>
                  The PKCS#12 file should contain the CA certificate, private key, and any intermediate certificates.
                </div>
                <div class="d-flex gap-2">
                  <button
                    type="submit"
                    class="btn btn-success"
                    :disabled="creatingCA || !importForm.file"
                  >
                    <span v-if="creatingCA" class="spinner-border spinner-border-sm me-2" role="status"></span>
                    Import CA
                  </button>
                  <button type="button" class="btn btn-secondary" @click="showAddCAModal = false">Cancel</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- CA Details Modal -->
    <div class="modal fade" :class="{ show: showCADetailsModal }" :style="{ display: showCADetailsModal ? 'block' : 'none' }" tabindex="-1">
      <div class="modal-dialog modal-xl">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">
              <i class="bi bi-shield-check me-2"></i>
              CA Details: {{ viewingCA?.name }}
            </h5>
            <button type="button" class="btn-close" @click="showCADetailsModal = false"></button>
          </div>
          <div class="modal-body" v-if="viewingCA">
            <div class="row">
              <!-- Basic Information -->
              <div class="col-lg-6 mb-4">
                <div class="card h-100">
                  <div class="card-header">
                    <h6 class="mb-0">
                      <i class="bi bi-info-circle me-2"></i>
                      Basic Information
                    </h6>
                  </div>
                  <div class="card-body">
                    <div class="row">
                      <div class="col-sm-4"><strong>Name:</strong></div>
                      <div class="col-sm-8">{{ viewingCA.name }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Serial:</strong></div>
                      <div class="col-sm-8"><code>{{ viewingCA.serial_number }}</code></div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Key Size:</strong></div>
                      <div class="col-sm-8">{{ viewingCA.key_size }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Algorithm:</strong></div>
                      <div class="col-sm-8">{{ viewingCA.signature_algorithm }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Type:</strong></div>
                      <div class="col-sm-8">
                        <span class="badge" :class="viewingCA.is_self_signed ? 'bg-success' : 'bg-info'">
                          {{ viewingCA.is_self_signed ? 'Self-Signed' : 'Imported' }}
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
                    <h6 class="mb-0">
                      <i class="bi bi-calendar-check me-2"></i>
                      Validity
                    </h6>
                  </div>
                  <div class="card-body">
                    <div class="row">
                      <div class="col-sm-4"><strong>Created:</strong></div>
                      <div class="col-sm-8">{{ formatDate(viewingCA.created_on) }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Expires:</strong></div>
                      <div class="col-sm-8">{{ formatDate(viewingCA.valid_until) }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Status:</strong></div>
                      <div class="col-sm-8">
                        <span class="badge" :class="getStatusClass(viewingCA)">
                          {{ getStatusText(viewingCA) }}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Subject -->
              <div class="col-lg-6 mb-4">
                <div class="card h-100">
                  <div class="card-header">
                    <h6 class="mb-0">
                      <i class="bi bi-person me-2"></i>
                      Subject
                    </h6>
                  </div>
                  <div class="card-body">
                    <pre class="mb-0 text-break small">{{ viewingCA.subject }}</pre>
                  </div>
                </div>
              </div>

              <!-- Issuer -->
              <div class="col-lg-6 mb-4">
                <div class="card h-100">
                  <div class="card-header">
                    <h6 class="mb-0">
                      <i class="bi bi-building me-2"></i>
                      Issuer
                    </h6>
                  </div>
                  <div class="card-body">
                    <pre class="mb-0 text-break small">{{ viewingCA.issuer }}</pre>
                  </div>
                </div>
              </div>
            </div>

            <!-- Certificate PEM -->
            <div class="card">
              <div class="card-header d-flex justify-content-between align-items-center">
                <h6 class="mb-0">
                  <i class="bi bi-file-earmark-text me-2"></i>
                  Certificate (PEM Format)
                </h6>
                <div class="btn-group btn-group-sm">
                  <button class="btn btn-outline-secondary" @click="copyToClipboard(viewingCA.certificate_pem)">
                    <i class="bi bi-clipboard me-1"></i>
                    Copy
                  </button>
                  <button class="btn btn-outline-primary" @click="downloadCACertificate(viewingCA)">
                    <i class="bi bi-download me-1"></i>
                    Download
                  </button>
                </div>
              </div>
              <div class="card-body">
                <pre class="certificate-pem mb-0">{{ viewingCA.certificate_pem }}</pre>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="showCADetailsModal = false">Close</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div class="modal fade" :class="{ show: showDeleteModal }" :style="{ display: showDeleteModal ? 'block' : 'none' }" tabindex="-1">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title text-danger">
              <i class="bi bi-exclamation-triangle me-2"></i>
              Delete Certificate Authority
            </h5>
            <button type="button" class="btn-close" @click="showDeleteModal = false"></button>
          </div>
          <div class="modal-body">
            <p>Are you sure you want to delete the Certificate Authority <strong>{{ deletingCA?.name }}</strong>?</p>
            <div class="alert alert-danger">
              <i class="bi bi-exclamation-triangle me-2"></i>
              <strong>Warning:</strong> This action cannot be undone. All certificates issued by this CA will become invalid.
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="showDeleteModal = false">Cancel</button>
            <button
              type="button"
              class="btn btn-danger"
              :disabled="deletingCAInProgress"
              @click="performDeleteCA"
            >
              <span v-if="deletingCAInProgress" class="spinner-border spinner-border-sm me-2" role="status"></span>
              Delete CA
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useAuthStore } from '@/stores/auth';
import { fetchCAs, createSelfSignedCA, importCAFromFile, deleteCA, downloadCA } from '@/api/certificates';
import { UserRole } from '@/types/User';
import type { CA } from '@/types/CA';
import ApiClient from '@/api/ApiClient';

const authStore = useAuthStore();

const isAdmin = computed(() => authStore.current_user?.role === UserRole.Admin);

const cas = ref<CA[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);

const selectedCA = ref<CA | null>(null);
const showAddCAModal = ref(false);
const showCADetailsModal = ref(false);
const showDeleteModal = ref(false);

const caCreationType = ref<'self-signed' | 'import' | null>(null);
const creatingCA = ref(false);
const deletingCAInProgress = ref(false);

const selfSignedForm = ref({
  name: '',
  validityYears: 10,
  password: ''
});

const importForm = ref({
  file: null as File | null,
  password: ''
});

const viewingCA = ref<CA | null>(null);
const deletingCA = ref<CA | null>(null);

const fileInput = ref<HTMLInputElement | null>(null);

const loadCAs = async () => {
  try {
    loading.value = true;
    error.value = null;
    cas.value = await fetchCAs();
  } catch (err: any) {
    console.error('Failed to load CAs:', err);
    error.value = `Failed to load CAs: ${err.message}`;
  } finally {
    loading.value = false;
  }
};

const viewCADetails = (ca: CA) => {
  viewingCA.value = ca;
  showCADetailsModal.value = true;
};

const handleDownloadCA = async (ca: CA) => {
  try {
    const response = await fetch('/api/certificates/ca/download', {
      method: 'GET',
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error(`Download failed: ${response.status}`);
    }

    const blob = await response.blob();
    const blobUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `${ca.name.replace(/[^a-zA-Z0-9]/g, '_')}.crt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(blobUrl);
  } catch (err: any) {
    console.error('Failed to download CA:', err);
    alert('Failed to download CA certificate');
  }
};



const confirmDeleteCA = (ca: CA) => {
  deletingCA.value = ca;
  showDeleteModal.value = true;
};

const createSelfSignedCAWrapper = async () => {
  try {
    creatingCA.value = true;
    const id = await createSelfSignedCA(selfSignedForm.value.name, selfSignedForm.value.validityYears, selfSignedForm.value.password || undefined);
    console.log('Created CA with ID:', id);
    await loadCAs();
    showAddCAModal.value = false;
    resetForms();
  } catch (err: any) {
    console.error('Failed to create CA:', err);
    alert(`Failed to create CA: ${err.message}`);
  } finally {
    creatingCA.value = false;
  }
};

const importCA = async () => {
  if (!importForm.value.file) return;

  const formData = new FormData();
  formData.append('file', importForm.value.file);
  formData.append('password', importForm.value.password);

  try {
    creatingCA.value = true;
    const id = await importCAFromFile(formData);
    console.log('Imported CA with ID:', id);
    await loadCAs();
    showAddCAModal.value = false;
    resetForms();
  } catch (err: any) {
    console.error('Failed to import CA:', err);
    alert(`Failed to import CA: ${err.message}`);
  } finally {
    creatingCA.value = false;
  }
};

const performDeleteCA = async () => {
  if (!deletingCA.value) return;

  try {
    deletingCAInProgress.value = true;
    await deleteCA(deletingCA.value.id);
    await loadCAs();
    showDeleteModal.value = false;
    deletingCA.value = null;
  } catch (err: any) {
    console.error('Failed to delete CA:', err);
    alert(`Failed to delete CA: ${err.message}`);
  } finally {
    deletingCAInProgress.value = false;
  }
};

const resetForms = () => {
  caCreationType.value = null;
  selfSignedForm.value = { name: '', validityYears: 10, password: '' };
  importForm.value = { file: null, password: '' };
  if (fileInput.value) {
    fileInput.value.value = '';
  }
};

const handleFileSelect = (event: Event) => {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0] || null;
  importForm.value.file = file;
};

const downloadCACertificate = async (ca: CA) => {
  // For now, use the general download. Need to implement per-CA download
  try {
    await downloadCA();
  } catch (err: any) {
    console.error('Failed to download CA certificate:', err);
    alert('Failed to download CA certificate');
  }
};

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    // Show temporary feedback
    const btn = event?.target as HTMLElement;
    if (btn) {
      const originalContent = btn.innerHTML;
      btn.innerHTML = '<i class="bi bi-check me-1"></i>Copied!';
      setTimeout(() => btn.innerHTML = originalContent, 2000);
    }
  } catch (err) {
    console.error('Failed to copy to clipboard:', err);
    // Fallback for older browsers
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand('copy');
    document.body.removeChild(textArea);
  }
};

const formatDate = (timestamp: number): string => {
  return new Date(timestamp).toLocaleDateString();
};

const getStatusText = (ca: CA): string => {
  const now = Date.now();
  const validUntil = ca.valid_until;

  if (validUntil < now) {
    return 'Expired';
  } else if (validUntil < now + (30 * 24 * 60 * 60 * 1000)) { // 30 days
    return 'Expiring Soon';
  } else {
    return 'Valid';
  }
};

const getStatusClass = (ca: CA): string => {
  const status = getStatusText(ca);
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

onMounted(() => {
  loadCAs();
});

// Close modals when clicking outside
// This could be improved with a modal component
</script>

<style scoped>
.ca-tools-container {
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

.table th {
  border-top: none;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.875rem;
  letter-spacing: 0.025em;
}

.table-hover tbody tr:hover {
  background-color: rgba(0, 0, 123, 0.075);
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

.btn-group-sm .btn {
  padding: 0.25rem 0.5rem;
}

.badge {
  font-size: 0.75rem;
}

@media (max-width: 768px) {
  .ca-tools-container {
    padding: 10px;
  }

  .d-flex.justify-content-between {
    flex-direction: column;
    gap: 1rem;
  }

  .table-responsive {
    font-size: 0.875rem;
  }

  .btn-group {
    flex-direction: column;
  }
}

/* Modal styles */
.modal-backdrop {
  background-color: rgba(0, 0, 0, 0.5);
}

.modal {
  display: none;
}

.modal.show {
  display: block;
}

.modal-dialog {
  margin: 1.75rem auto;
}

@media (min-width: 576px) {
  .modal-dialog {
    max-width: 500px;
    margin: 1.75rem auto;
  }

  .modal-lg {
    max-width: 800px;
  }

  .modal-xl {
    max-width: 1140px;
  }
}
</style>
