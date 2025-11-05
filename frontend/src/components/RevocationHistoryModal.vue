<template>
  <div
      v-if="isVisible"
      class="modal show d-block"
      tabindex="-1"
      style="background: rgba(0, 0, 0, 0.5)"
  >
    <div class="modal-dialog modal-xl">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">
            <i class="bi bi-clock-history me-2"></i>
            Certificate Revocation History
          </h5>
          <button type="button" class="btn-close" @click="close"></button>
        </div>
        <div class="modal-body">
          <div v-if="loading" class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
              <span class="visually-hidden">Loading...</span>
            </div>
            <div class="mt-2">Loading revocation history...</div>
          </div>

          <div v-else-if="error" class="alert alert-danger">
            <i class="bi bi-exclamation-triangle me-2"></i>
            {{ error }}
          </div>

          <div v-else-if="revocationHistory.length === 0" class="text-center py-4 text-muted">
            <i class="bi bi-info-circle fs-1 mb-3"></i>
            <h6>No certificates have been revoked yet</h6>
            <p class="mb-0">Revocation history will appear here once certificates are revoked.</p>
          </div>

          <div v-else>
            <div class="mb-3">
              <div class="row">
                <div class="col-md-6">
                  <strong>Total Revocations:</strong> {{ revocationHistory.length }}
                </div>
                <div class="col-md-6 text-end">
                  <small class="text-muted">Last updated: {{ formatDate(Date.now()) }}</small>
                </div>
              </div>
            </div>

            <div class="table-responsive">
              <table class="table table-hover">
                <thead class="table-light">
                  <tr>
                    <th>Certificate</th>
                    <th>Revoked On</th>
                    <th>Reason</th>
                    <th>Revoked By</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="record in revocationHistory" :key="record.id">
                    <td>
                      <div>
                        <strong>{{ getCertificateName(record.certificate_id) }}</strong>
                        <br>
                        <small class="text-muted">ID: {{ record.certificate_id }}</small>
                      </div>
                    </td>
                    <td>{{ formatDate(record.revocation_date) }}</td>
                    <td>
                      <span class="badge" :class="getReasonBadgeClass(record.revocation_reason)">
                        {{ getRevocationReasonText(record.revocation_reason) }}
                      </span>
                    </td>
                    <td>
                      <div v-if="record.revoked_by_user_id">
                        {{ getUserName(record.revoked_by_user_id) }}
                      </div>
                      <div v-else class="text-muted">
                        <em>System</em>
                      </div>
                    </td>
                    <td>
                      <button
                          class="btn btn-sm btn-outline-primary me-1"
                          @click="viewCertificate(record.certificate_id)"
                          title="View Certificate Details"
                      >
                        <i class="bi bi-eye"></i>
                      </button>
                      <button
                          class="btn btn-sm btn-outline-secondary"
                          @click="downloadCertificate(record.certificate_id, getCertificateName(record.certificate_id))"
                          title="Download Certificate"
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
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" @click="close">Close</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {ref, onMounted, computed, watch} from 'vue';
import {useCertificateStore} from '@/stores/certificates';
import {useUserStore} from '@/stores/users';
import {getRevocationHistory, downloadCertificate as downloadCertApi} from '@/api/certificates';

interface RevocationRecord {
  id: number;
  certificate_id: number;
  revocation_date: number;
  revocation_reason: number;
  revoked_by_user_id?: number;
}

interface Props {
  isVisible: boolean;
}

interface Emits {
  (e: 'close'): void;
}

const props = defineProps<Props>();
const emit = defineEmits<Emits>();

const certificateStore = useCertificateStore();
const userStore = useUserStore();

const revocationHistory = ref<RevocationRecord[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);

// Computed properties for certificate and user name lookups
const certificates = computed(() => certificateStore.certificates);
const users = computed(() => userStore.users);

const getCertificateName = (certId: number): string => {
  const cert = Array.from(certificates.value.values()).find(c => c.id === certId);
  return cert?.name || `Certificate ${certId}`;
};

const getUserName = (userId: number): string => {
  const user = Array.from(users.value.values()).find(u => u.id === userId);
  return user?.name || `User ${userId}`;
};

const getRevocationReasonText = (reason: number): string => {
  switch (reason) {
    case 0: return 'Unspecified';
    case 1: return 'Key Compromise';
    case 2: return 'CA Compromise';
    case 3: return 'Affiliation Changed';
    case 4: return 'Superseded';
    case 5: return 'Cessation of Operation';
    case 6: return 'Certificate Hold';
    case 8: return 'Remove from CRL';
    case 9: return 'Privilege Withdrawn';
    case 10: return 'AA Compromise';
    default: return 'Unknown';
  }
};

const getReasonBadgeClass = (reason: number): string => {
  switch (reason) {
    case 1: return 'bg-danger'; // Key Compromise - critical
    case 2: return 'bg-danger'; // CA Compromise - critical
    case 3: return 'bg-warning text-dark'; // Affiliation Changed
    case 4: return 'bg-info'; // Superseded
    case 5: return 'bg-secondary'; // Cessation of Operation
    case 6: return 'bg-warning text-dark'; // Certificate Hold
    case 8: return 'bg-info'; // Remove from CRL
    case 9: return 'bg-warning text-dark'; // Privilege Withdrawn
    case 10: return 'bg-danger'; // AA Compromise - critical
    default: return 'bg-light text-dark'; // Unspecified
  }
};

const formatDate = (timestamp: number): string => {
  return new Date(timestamp).toLocaleString();
};

const loadRevocationHistory = async () => {
  loading.value = true;
  error.value = null;

  try {
    revocationHistory.value = await getRevocationHistory();
  } catch (err) {
    console.error('Failed to load revocation history:', err);
    error.value = 'Failed to load revocation history. Please try again.';
  } finally {
    loading.value = false;
  }
};

const viewCertificate = (certId: number) => {
  // Emit event to parent to show certificate details
  // This would need to be handled by the parent component
  console.log('View certificate:', certId);
};

const downloadCertificate = async (certId: number, certName: string) => {
  try {
    await downloadCertApi(certId, certName);
  } catch (err) {
    console.error('Failed to download certificate:', err);
    alert('Failed to download certificate. Please try again.');
  }
};

const close = () => {
  emit('close');
};

// Load data when modal becomes visible
watch(() => props.isVisible, (newVisible) => {
  if (newVisible) {
    loadRevocationHistory();
  }
});

// Load user data when component mounts
onMounted(async () => {
  await userStore.fetchUsers();
});
</script>

<style scoped>
.modal {
  z-index: 1055; /* Higher than other modals */
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

.badge {
  font-size: 0.75rem;
}
</style>
