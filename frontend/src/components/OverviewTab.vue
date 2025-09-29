<template>
  <div class="overview-container">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h1 class="mb-0">Certificates</h1>
      <div class="d-flex gap-2">
        <button
            id="CreateCertificateButton"
            v-if="authStore.isAdmin"
            class="btn btn-primary"
            @click="showGenerateModal"
        >
          Create New Certificate
        </button>
      </div>
    </div>
    <div class="card">
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover mb-0">
            <thead class="table-light">
              <tr>
                <th v-if="authStore.isAdmin">User</th>
                <th>Name</th>
                <th class="d-none d-sm-table-cell">Type</th>
                <th class="d-none d-sm-table-cell">Created on</th>
                <th>Valid until</th>
                <th>Password</th>
                <th class="d-none d-sm-table-cell">Renew Method</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="cert in certificates.values()" :key="cert.id">
                <td :id="'UserId-' + cert.id" v-if="authStore.isAdmin">{{ userStore.idToName(cert.user_id) }}</td>
                <td :id="'CertName-' + cert.id" >{{ cert.name }}</td>
                <td :id="'CertType-' + cert.id" class="d-none d-sm-table-cell">{{ CertificateType[cert.certificate_type] }}</td>
                <td :id="'CreatedOn-' + cert.id" class="d-none d-sm-table-cell">{{ new Date(cert.created_on).toLocaleDateString() }}</td>
                <td :id="'ValidUntil-' + cert.id" >{{ new Date(cert.valid_until).toLocaleDateString() }}</td>
                <td :id="'Password-' + cert.id"  class="password-cell">
                  <div class="d-flex align-items-center">
                    <template v-if="shownCerts.has(cert.id)">
                      <input
                          :id="'PasswordInput-' + cert.id"
                          type="text"
                          :value="cert.pkcs12_password"
                          readonly
                          class="form-control form-control-sm me-2"
                          style="font-family: monospace; max-width: 100px;"
                      />
                    </template>
                    <template v-else>
                      <span>•••••••</span>
                    </template>
                    <img
                        :id="'PasswordButton-' + cert.id"
                        :src="shownCerts.has(cert.id) ? '/images/eye-open.png' : '/images/eye-hidden.png'"
                        class="ms-2"
                        style="width: 20px; cursor: pointer;"
                        @click="togglePasswordShown(cert)"
                        alt="Button to show / hide password"
                    />
                  </div>
                </td>
                <td :id="'RenewMethod-' + cert.id" class="d-none d-sm-table-cell">{{ CertificateRenewMethod[cert.renew_method] }}</td>
                <td>
                  <div class="d-flex flex-sm-row flex-column gap-1">
                    <button
                        :id="'ViewButton-' + cert.id"
                        class="btn btn-primary btn-sm"
                        @click="viewCertificateDetails(cert.id)"
                        title="View Certificate Details"
                    >
                      <i class="bi bi-eye"></i> View
                    </button>
                    <button
                        :id="'DownloadButton-' + cert.id"
                        class="btn btn-primary btn-sm flex-grow-1"
                        @click="downloadCertificate(cert.id)"
                        title="Download Certificate"
                    >
                      Download
                    </button>
                    <button
                        :id="'DeleteButton-' + cert.id"
                        v-if="authStore.isAdmin"
                        class="btn btn-danger btn-sm flex-grow-1"
                        @click="confirmDeletion(cert)"
                        title="Delete Certificate"
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

    <div v-if="loading" class="text-center mt-3">Loading certificates...</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

    <!-- Generate Certificate Modal -->
    <div
        v-if="isGenerateModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Generate New Certificate</h5>
            <button type="button" class="btn-close" @click="closeGenerateModal"></button>
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
                <option :value="CertificateType.Client">Client</option>
                <option :value="CertificateType.Server">Server</option>
              </select>
            </div>
            <div class="mb-3">
              <label for="caId" class="form-label">Certificate Authority (CA)</label>
              <select
                  id="caId"
                  v-model="certReq.ca_id"
                  class="form-control"
              >
                <option value="" disabled>Select a CA</option>
                <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                  {{ ca.name }} ({{ ca.is_self_signed ? 'Self-Signed' : 'Imported' }})
                </option>
              </select>
              <div class="form-text">
                Choose which CA to use for signing this certificate.
              </div>
            </div>
            <div class="mb-3" v-if="certReq.cert_type == CertificateType.Server">
              <label class="form-label">DNS Names</label>
              <div v-for="(_, index) in certReq.dns_names" :key="index" class="input-group mb-2">
                <input
                    type="text"
                    class="form-control"
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
            <div class="mb-3">
              <label for="userId" class="form-label">User</label>
              <select
                  id="userId"
                  v-model="certReq.user_id"
                  class="form-control"
              >
                <option value="" disabled>Select a user</option>
                <option v-for="user in userStore.users" :key="user.id" :value="user.id">
                  {{ user.name }}
                </option>
              </select>
            </div>
            <div class="mb-3">
              <label for="validity" class="form-label">Validity (years)</label>
              <input
                  id="validity"
                  v-model.number="certReq.validity_in_years"
                  type="number"
                  class="form-control"
                  min="1"
                  placeholder="Enter validity period"
              />
            </div>
            <div class="mb-3 form-check form-switch">
              <input
                  type="checkbox"
                  class="form-check-input"
                  id="systemGeneratedPassword"
                  v-model="certReq.system_generated_password"
                  :disabled="passwordRule == PasswordRule.System"
                  role="switch"
              />
              <label class="form-check-label" for="system_generated_password">
                System Generated Password
              </label>
            </div>
            <div class="mb-3" v-if="!certReq.system_generated_password">
              <label for="certPassword" class="form-label">Password</label>
              <input
                  id="certPassword"
                  v-model="certReq.pkcs12_password"
                  type="text"
                  class="form-control"
                  placeholder="Enter password"
              />
            </div>
            <div class="mb-3">
              <label for="renewMethod" class="form-label">Certificate Renew Method</label>
              <select
                  class="form-select"
                  id="renewMethod"
                  v-model="certReq.renew_method"
                  required
              >
                <option :value="CertificateRenewMethod.None">None</option>
                <option :value="CertificateRenewMethod.Notify">Remind</option>
                <option :value="CertificateRenewMethod.Renew">Renew</option>
                <option :value="CertificateRenewMethod.RenewAndNotify">Renew and Notify</option>
              </select>
            </div>
            <div v-if="isMailValid" class="mb-3 form-check form-switch">
              <input
                  type="checkbox"
                  class="form-check-input"
                  id="notify-user"
                  v-model="certReq.notify_user"
                  role="switch"
              />
              <label class="form-check-label" for="notify-user">
                Notify User
              </label>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeGenerateModal">
              Cancel
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || ((!certReq.system_generated_password && certReq.pkcs12_password.length == 0) && passwordRule == PasswordRule.Required)"
                @click="createCertificate"
            >
              <span v-if="loading">Creating...</span>
              <span v-else>Create Certificate</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div
        v-if="isDeleteModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Delete Certificate</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>
              Are you sure you want to delete the certificate
              <strong>{{ certToDelete?.name }}</strong>?
            </p>
            <p class="text-warning">
              <small>
                Disclaimer: Deleting the certificate will not revoke it. The certificate will remain
                valid until its expiration date.
              </small>
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              Cancel
            </button>
            <button type="button" class="btn btn-danger" @click="deleteCertificate">
              Delete
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Certificate Details Modal -->
    <div
        v-if="isCertificateDetailsModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog modal-xl">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">
              <i class="bi bi-file-earmark-text me-2"></i>
              Certificate Details: {{ certificateDetails?.name }}
            </h5>
            <button type="button" class="btn-close" @click="closeCertificateDetailsModal"></button>
          </div>
          <div class="modal-body" v-if="certificateDetails">
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
                      <div class="col-sm-8">{{ certificateDetails.name }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Serial:</strong></div>
                      <div class="col-sm-8"><code>{{ certificateDetails.serial_number }}</code></div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Key Size:</strong></div>
                      <div class="col-sm-8">{{ certificateDetails.key_size }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Algorithm:</strong></div>
                      <div class="col-sm-8">{{ certificateDetails.signature_algorithm }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Type:</strong></div>
                      <div class="col-sm-8">
                        <span class="badge" :class="certificateDetails.certificate_type === CertificateType.Client ? 'bg-primary' : 'bg-success'">
                          {{ CertificateType[certificateDetails.certificate_type] }}
                        </span>
                      </div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Renew Method:</strong></div>
                      <div class="col-sm-8">{{ CertificateRenewMethod[certificateDetails.renew_method] }}</div>
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
                      <div class="col-sm-8">{{ formatDate(certificateDetails.created_on) }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Expires:</strong></div>
                      <div class="col-sm-8">{{ formatDate(certificateDetails.valid_until) }}</div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4"><strong>Status:</strong></div>
                      <div class="col-sm-8">
                        <span class="badge" :class="getStatusClass(certificateDetails)">
                          {{ getStatusText(certificateDetails) }}
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
                    <pre class="mb-0 text-break small">{{ certificateDetails.subject }}</pre>
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
                    <pre class="mb-0 text-break small">{{ certificateDetails.issuer }}</pre>
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
                  <button class="btn btn-outline-secondary" @click="copyToClipboard(certificateDetails.certificate_pem)">
                    <i class="bi bi-clipboard me-1"></i>
                    Copy
                  </button>
                  <button class="btn btn-outline-primary" @click="downloadCertificate(certificateDetails.id)">
                    <i class="bi bi-download me-1"></i>
                    Download
                  </button>
                </div>
              </div>
              <div class="card-body">
                <pre class="certificate-pem mb-0">{{ certificateDetails.certificate_pem }}</pre>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeCertificateDetailsModal">Close</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
<script setup lang="ts">
import {computed, onMounted, reactive, ref, watch} from 'vue';
import {useCertificateStore} from '@/stores/certificates';
import {type Certificate, type CertificateDetails, CertificateRenewMethod, CertificateType} from "@/types/Certificate";
import type {CertificateRequirements} from "@/types/CertificateRequirements";
import type {CAAndCertificate} from "@/types/CA";
import {useAuthStore} from "@/stores/auth.ts";
import {useUserStore} from "@/stores/users.ts";
import {useSettingsStore} from "@/stores/settings.ts";
import {PasswordRule} from "@/types/Settings.ts";
import {downloadCA, fetchCAs, getCertificateDetails} from "@/api/certificates.ts";

// stores
const certificateStore = useCertificateStore();
const authStore = useAuthStore();
const userStore = useUserStore();
const settingStore = useSettingsStore();

// local state
const shownCerts = ref(new Set<number>());
const availableCAs = ref<CAAndCertificate[]>([]);

const certificates = computed(() => certificateStore.certificates);
const settings = computed(() => settingStore.settings);
const loading = computed(() => certificateStore.loading);
const error = computed(() => certificateStore.error);

const isDeleteModalVisible = ref(false);
const isGenerateModalVisible = ref(false);
const isCertificateDetailsModalVisible = ref(false);
const certToDelete = ref<Certificate | null>(null);
const certificateDetails = ref<CertificateDetails | null>(null);

const passwordRule = computed(() => {
  return settings.value?.common.password_rule ?? PasswordRule.Optional;
});

const certReq = reactive<CertificateRequirements>({
  cert_name: '',
  user_id: 0,
  validity_in_years: 1,
  system_generated_password: passwordRule.value == PasswordRule.System,
  pkcs12_password: '',
  notify_user: false,
  cert_type: CertificateType.Client,
  dns_names: [''],
  renew_method: CertificateRenewMethod.None,
});

const isMailValid = computed(() => {
  return (settings.value?.mail.smtp_host.length ?? 0) > 0 && (settings.value?.mail.smtp_port ?? 0) > 0;
});

watch(passwordRule, (newVal) => {
  certReq.system_generated_password = (newVal === PasswordRule.System);
}, { immediate: true });

onMounted(async () => {
  await certificateStore.fetchCertificates();
  await settingStore.fetchSettings();
  if (authStore.isAdmin) {
    await userStore.fetchUsers();
  }
});

const showGenerateModal = async () => {
  await userStore.fetchUsers();
  await fetchAvailableCAs();
  isGenerateModalVisible.value = true;
};

const fetchAvailableCAs = async () => {
  try {
    availableCAs.value = await fetchCAs();
  } catch (err) {
    console.error('Failed to fetch CAs:', err);
  }
};

const closeGenerateModal = () => {
  isGenerateModalVisible.value = false;
  certReq.cert_name = '';
  certReq.user_id = 0;
  certReq.validity_in_years = 1;
  certReq.pkcs12_password = '';
  certReq.notify_user = false;
};

const createCertificate = async () => {
    await certificateStore.createCertificate(certReq);
    closeGenerateModal();
};

const confirmDeletion = (cert: Certificate) => {
  certToDelete.value = cert;
  isDeleteModalVisible.value = true;
};

const closeDeleteModal = () => {
  certToDelete.value = null;
  isDeleteModalVisible.value = false;
};

const downloadCertificate = async (certId: number) => {
  await certificateStore.downloadCertificate(certId);
}

const deleteCertificate = async () => {
  if (certToDelete.value) {
    await certificateStore.deleteCertificate(certToDelete.value.id);
    closeDeleteModal();
  }
};

const togglePasswordShown = async (cert: Certificate) => {
  if (!cert.pkcs12_password) {
    await certificateStore.fetchCertificatePassword(cert.id);
  }

  if (shownCerts.value.has(cert.id)) {
    shownCerts.value.delete(cert.id);
  } else {
    shownCerts.value.add(cert.id);
  }
};

const addDNSField = () => {
  certReq.dns_names.push('');
};

const removeDNSField = (index: number) => {
  certReq.dns_names.splice(index, 1);
};

const viewCertificateDetails = async (certId: number) => {
  try {
    certificateDetails.value = await getCertificateDetails(certId);
    isCertificateDetailsModalVisible.value = true;
  } catch (err) {
    console.error('Failed to fetch certificate details:', err);
    alert('Failed to load certificate details');
  }
};

const closeCertificateDetailsModal = () => {
  isCertificateDetailsModalVisible.value = false;
  certificateDetails.value = null;
};

const formatDate = (timestamp: number): string => {
  return new Date(timestamp).toLocaleDateString();
};

const getStatusText = (cert: CertificateDetails): string => {
  const now = Date.now();
  const validUntil = cert.valid_until;

  if (validUntil < now) {
    return 'Expired';
  } else if (validUntil < now + (30 * 24 * 60 * 60 * 1000)) { // 30 days
    return 'Expiring Soon';
  } else {
    return 'Valid';
  }
};

const getStatusClass = (cert: CertificateDetails): string => {
  const status = getStatusText(cert);
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
</script>


<style scoped>
.overview-container {
  padding: 20px;
  background-color: transparent;
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

.modal {
  z-index: 1050;
  display: flex;
  align-items: center;
  justify-content: center;
}

/* When multiple modals are present, we want to stack them properly */
.modal + .modal {
  z-index: 1051;
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

@media (max-width: 768px) {
  .overview-container {
    padding: 10px;
  }
}
</style>
