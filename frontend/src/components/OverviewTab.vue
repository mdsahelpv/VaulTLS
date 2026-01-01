<template>
  <div class="overview-container">
    <!-- Root CA Mode Banner -->
    <div v-if="isRootCA" class="alert alert-warning mb-3">
      <i class="bi bi-shield-lock me-2"></i>
      <strong>Root CA Server Mode</strong>
      <p class="mb-0 mt-1">
        This instance is configured as a Root CA Server. Only subordinate CA certificates can be issued.
        Client and server certificates must be issued by importing subordinate CAs into other instances.
      </p>
    </div>

    <div class="d-flex justify-content-between align-items-center mb-3">
      <h1 class="mb-0">Certificates</h1>
      <div class="d-flex gap-2 align-items-center">
        <div class="d-flex align-items-center gap-2">
          <label for="statusFilter" class="form-label mb-0 fw-bold" title="Filter certificates by their current status">Filter:</label>
          <select
              id="statusFilter"
              v-model="statusFilter"
              class="form-select form-select-sm"
              style="width: auto; min-width: 140px;"
              title="Choose which certificates to display: All, Active (valid), Revoked, or Expired"
          >
            <option value="all" title="Show all certificates regardless of status">All Certificates</option>
            <option value="active" title="Show only valid, non-expired certificates">Active Only</option>
            <option value="revoked" title="Show only revoked certificates">Revoked Only</option>
            <option value="expired" title="Show only expired certificates">Expired Only</option>
          </select>
        </div>
        <button
            id="CreateCertificateButton"
            v-if="authStore.isAdmin"
            class="btn btn-primary me-2"
            @click="openGenerateModal"
        >
          {{ isRootCA ? 'Create Subordinate CA' : 'Create New Certificate' }}
        </button>
        <button
            id="SignCSRButton"
            v-if="authStore.isAdmin"
            class="btn btn-success me-2"
            @click="showSignCSRModalFunction"
            title="Sign Certificate Signing Request (CSR) with available CAs"
        >
          <i class="bi bi-file-earmark-plus"></i> Sign CSR
        </button>
        <button
            v-if="authStore.isAdmin"
            class="btn btn-warning"
            @click="showRevocationHistory = true"
            title="View Certificate Revocation History"
        >
          <i class="bi bi-clock-history me-1"></i>
          Revocation History
        </button>
      </div>
    </div>

    <!-- Bulk Actions Toolbar -->
    <div v-if="authStore.isAdmin && selectedCertificates.size > 0" class="mb-3 p-3 bg-light rounded">
      <div class="d-flex justify-content-between align-items-center">
        <div>
          <strong>{{ selectedCertificates.size }} certificate{{ selectedCertificates.size > 1 ? 's' : '' }} selected</strong>
        </div>
        <div class="d-flex gap-2">
          <button
              class="btn btn-warning btn-sm"
              @click="confirmBulkRevocation"
              title="Revoke all selected certificates with a single operation"
          >
            <i class="bi bi-x-circle me-1"></i>
            Revoke Selected ({{ selectedCertificates.size }})
          </button>
          <button
              class="btn btn-secondary btn-sm"
              @click="clearSelection"
              title="Clear all certificate selections"
          >
            Clear Selection
          </button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead class="table-light">
              <tr>
                <th v-if="authStore.isAdmin" class="text-center" title="Select certificates for bulk operations">
                  <input
                      type="checkbox"
                      :checked="selectedCertificates.size > 0 && selectedCertificates.size === selectableCertificates.length"
                      :indeterminate="selectedCertificates.size > 0 && selectedCertificates.size < selectableCertificates.length"
                      @change="toggleSelectAll"
                      class="form-check-input"
                      title="Select/deselect all active certificates for bulk revocation"
                  />
                </th>
                <th v-if="authStore.isAdmin">User</th>
                <th>Name</th>
                <th class="d-none d-sm-table-cell">Type</th>
                <th class="d-none d-sm-table-cell">Created on</th>
                <th>Valid until</th>
                <th>Status</th>
                <th>Password</th>
                <th class="d-none d-sm-table-cell">Renew Method</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="cert in filteredCertificates" :key="cert.id">
                <td v-if="authStore.isAdmin" class="text-center">
                  <input
                      type="checkbox"
                      :checked="selectedCertificates.has(cert.id)"
                      :disabled="cert.is_revoked"
                      @change="toggleCertificateSelection(cert.id)"
                      class="form-check-input"
                      :title="cert.is_revoked ? 'Revoked certificates cannot be selected for bulk operations' : `Select ${cert.name} for bulk revocation`"
                  />
                </td>
                <td :id="'UserId-' + cert.id" v-if="authStore.isAdmin">{{ userStore.idToName(cert.user_id) }}</td>
                <td :id="'CertName-' + cert.id" >{{ cert.name }}</td>
                <td :id="'CertType-' + cert.id" class="d-none d-sm-table-cell">{{ CertificateType[cert.certificate_type] }}</td>
                <td :id="'CreatedOn-' + cert.id" class="d-none d-sm-table-cell">{{ new Date(cert.created_on).toLocaleDateString() }}</td>
                <td :id="'ValidUntil-' + cert.id" >{{ new Date(cert.valid_until).toLocaleDateString() }}</td>
                <td :id="'Status-' + cert.id">
                  <span class="badge" :class="getCertificateStatusClass(cert)" :title="getCertificateStatusTooltip(cert)">
                    {{ getCertificateStatusText(cert) }}
                  </span>
                </td>
                <td :id="'Password-' + cert.id" class="password-cell">
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
                    <button
                        v-if="shownCerts.has(cert.id) && cert.pkcs12_password"
                        :id="'CopyPasswordButton-' + cert.id"
                        class="btn btn-outline-primary btn-sm ms-1"
                        @click="copyPasswordToClipboard(cert)"
                        title="Copy password to clipboard"
                    >
                      <i class="bi bi-clipboard me-1"></i>Copy
                    </button>
                    <img
                        :id="'PasswordButton-' + cert.id"
                        :src="shownCerts.has(cert.id) ? '/images/eye-open.png' : '/images/eye-hidden.png'"
                        class="ms-1"
                        style="width: 20px; cursor: pointer;"
                        @click="togglePasswordShown(cert)"
                        :title="shownCerts.has(cert.id) ? 'Hide password' : 'Show password'"
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
                        @click="handleDownload({id: cert.id, name: cert.name})"
                        title="Download Certificate"
                    >
                      Download
                    </button>
                    <button
                        :id="'RevokeButton-' + cert.id"
                        v-if="authStore.isAdmin && !cert.is_revoked"
                        class="btn btn-warning btn-sm flex-grow-1"
                        @click="confirmRevocation(cert)"
                        title="Revoke Certificate"
                    >
                      <i class="bi bi-x-circle"></i> Revoke
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

    <div v-if="loading" class="text-center mt-3">Loading certificates...</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

    <!-- Generate Certificate Modal -->
    <CertificateCreateModal
      v-model="isGenerateModalVisible"
      :is-root-ca="isRootCA"
      :available-cas="availableCAs"
      :users="userStore.users"
      :password-rule="passwordRule"
      @certificate-created="onCertificateCreated"
    />

    <!-- Revoke Confirmation Modal -->
    <div
        v-if="isRevokeModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Revoke Certificate</h5>
            <button type="button" class="btn-close" @click="closeRevokeModal"></button>
          </div>
          <div class="modal-body">
            <p v-if="selectedCertificates.size > 0">
              Are you sure you want to revoke
              <strong>{{ selectedCertificates.size }} certificate{{ selectedCertificates.size > 1 ? 's' : '' }}</strong>?
            </p>
            <p v-else>
              Are you sure you want to revoke the certificate
              <strong>{{ certToRevoke?.name }}</strong>?
            </p>
            <p class="text-warning">
              <strong>Warning:</strong> Revoking {{ selectedCertificates.size > 0 ? 'these certificates' : 'a certificate' }} will immediately invalidate {{ selectedCertificates.size > 0 ? 'them' : 'it' }}.
              Any systems using {{ selectedCertificates.size > 0 ? 'these certificates' : 'this certificate' }} will no longer trust {{ selectedCertificates.size > 0 ? 'them' : 'it' }}.
            </p>
            <div class="mb-3">
              <label for="revocationReason" class="form-label" title="Select the reason for revoking this certificate">Revocation Reason</label>
              <select
                  id="revocationReason"
                  v-model.number="revocationReason"
                  class="form-select"
                  required
                  title="Choose the appropriate RFC 5280 standard revocation reason"
              >
                <option :value="0" title="No specific reason given (RFC 5280: unspecified)">Unspecified</option>
                <option :value="1" title="Private key compromised (RFC 5280: keyCompromise)">Key Compromise</option>
                <option :value="2" title="CA certificate compromised (RFC 5280: cACompromise)">CA Compromise</option>
                <option :value="3" title="Affiliation or business relationship changed (RFC 5280: affiliationChanged)">Affiliation Changed</option>
                <option :value="4" title="Certificate has been replaced (RFC 5280: superseded)">Superseded</option>
                <option :value="5" title="Certificate operation ceased (RFC 5280: cessationOfOperation)">Cessation of Operation</option>
                <option :value="6" title="Certificate temporarily suspended (RFC 5280: certificateHold)">Certificate Hold</option>
                <option :value="7" title="Remove from CRL (RFC 5280: removeFromCRL)">Remove from CRL</option>
                <option :value="8" title="Certificate privileges withdrawn (RFC 5280: privilegeWithdrawn)">Privilege Withdrawn</option>
                <option :value="9" title="Authority compromised (RFC 5280: aACompromise)">AA Compromise</option>
              </select>
              <div class="form-text">
                Choose the RFC 5280 standard revocation reason that best fits the situation.
              </div>
            </div>
            <div v-if="isMailValid" class="mb-3 form-check form-switch">
              <input
                  type="checkbox"
                  class="form-check-input"
                  id="notify-user-revoke"
                  v-model="notifyUserOnRevoke"
                  role="switch"
              />
              <label class="form-check-label" for="notify-user-revoke">
                Notify Certificate Owner
              </label>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeRevokeModal">
              Cancel
            </button>
            <button type="button" class="btn btn-warning" @click="revokeCertificate" :disabled="!isRevokeValid">
              <i class="bi bi-x-circle me-1"></i>
              Revoke Certificate
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
                          <!-- eslint-disable-next-line -->
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
                    <!-- Revocation Information -->
                    <template v-if="certificateDetails.is_revoked">
                      <hr>
                      <div class="row">
                        <div class="col-sm-4"><strong>Revoked:</strong></div>
                        <div class="col-sm-8">{{ formatDate(certificateDetails.revoked_on!) }}</div>
                      </div>
                      <hr>
                      <div class="row">
                        <div class="col-sm-4"><strong>Revocation Reason:</strong></div>
                        <div class="col-sm-8">
                          <span class="badge bg-secondary">{{ getRevocationReasonText(certificateDetails.revoked_reason!) }}</span>
                        </div>
                      </div>
                      <hr>
                      <div class="row">
                        <div class="col-sm-4"><strong>Revoked By:</strong></div>
                        <div class="col-sm-8">{{ userStore.idToName(certificateDetails.revoked_by!) }}</div>
                      </div>
                                        </template>
                                      </div>
                                    </div>
                                  </div>              </div>

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
                  <button class="btn btn-outline-secondary" @click="copyToClipboard((certificateDetails as CertificateDetails).certificate_pem)">
                    <i class="bi bi-clipboard me-1"></i>
                    Copy
                  </button>
                  <button class="btn btn-outline-primary" @click="handleDownload({id: (certificateDetails as CertificateDetails).id, name: (certificateDetails as CertificateDetails).name})">
                    <i class="bi bi-download me-1"></i>
                    Download
                  </button>
                </div>
              </div>
              <div class="card-body">
                <pre class="certificate-pem mb-0">{{ (certificateDetails as CertificateDetails).certificate_pem }}</pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Revocation History Modal -->
    <RevocationHistoryModal
        :isVisible="showRevocationHistory"
        @close="showRevocationHistory = false"
    />

    <!-- Download Format Selection Modal -->
    <div
        v-if="showDownloadModal"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Select Download Format</h5>
            <button type="button" class="btn-close" @click="showDownloadModal = false"></button>
          </div>
          <div class="modal-body">
            <p class="text-muted mb-3">
              Choose the format for downloading the certificate:
            </p>

            <div class="mb-3">
              <div class="form-check">
                <input
                    class="form-check-input"
                    type="radio"
                    v-model="selectedFormat"
                    id="formatPkcs12"
                    value="pkcs12"
                />
                <label class="form-check-label fw-bold" for="formatPkcs12">
                  PKCS#12 (.p12)
                </label>
                <div class="form-text">
                  Full bundle with certificate, private key, CA chain, and password protection
                </div>
              </div>
            </div>

            <div class="mb-3">
              <div class="form-check">
                <input
                    class="form-check-input"
                    type="radio"
                    v-model="selectedFormat"
                    id="formatPemKey"
                    value="pem_key"
                />
                <label class="form-check-label fw-bold" for="formatPemKey">
                  PEM + Key (.zip)
                </label>
                <div class="form-text">
                  Separate files: certificate.pem + private_key.key in a ZIP archive
                </div>
              </div>
            </div>

            <div class="mb-3">
              <div class="form-check">
                <input
                    class="form-check-input"
                    type="radio"
                    v-model="selectedFormat"
                    id="formatPem"
                    value="pem"
                />
                <label class="form-check-label fw-bold" for="formatPem">
                  PEM (.pem)
                </label>
                <div class="form-text">
                  Certificate only in text format
                </div>
              </div>
            </div>

            <div class="mb-3">
              <div class="form-check">
                <input
                    class="form-check-input"
                    type="radio"
                    v-model="selectedFormat"
                    id="formatDer"
                    value="der"
                />
                <label class="form-check-label fw-bold" for="formatDer">
                  DER (.der)
                </label>
                <div class="form-text">
                  Certificate only in binary format
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="showDownloadModal = false">
              Cancel
            </button>
            <button type="button" class="btn btn-primary" @click="confirmDownload">
              Download
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- CSR Signing Modal -->
    <div
        v-if="showSignCSRModal"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">
              <i class="bi bi-file-earmark-plus me-2"></i>
              Sign Certificate Signing Request (CSR)
            </h5>
            <button type="button" class="btn-close" @click="closeSignCSRModal"></button>
          </div>
          <div class="modal-body">
            <div class="row">
              <!-- CSR Upload Section -->
              <div class="col-md-8 mb-4">
                <h6 class="mb-3">CSR File Upload</h6>

                <!-- Drag & Drop Zone -->
                <div
                  class="border border-2 border-dashed rounded p-4 text-center"
                  :class="csrSignData.csr_file ? 'border-success bg-light' : 'border-primary'"
                  @dragover.prevent="handleDragOver"
                  @dragleave.prevent="handleDragLeave"
                  @drop.prevent="handleFileDrop"
                  style="cursor: pointer; transition: all 0.2s;"
                >
                  <div v-if="!csrSignData.csr_file">
                    <i class="bi bi-cloud-upload text-primary" style="font-size: 2rem;"></i>
                    <p class="mb-2 mt-2 fw-bold">Drag & drop your CSR file here</p>
                    <p class="text-muted small">Or click to browse files</p>
                    <p class="text-muted small mb-3">Supported formats: .csr, .pem, .der (Max: 100KB)</p>
                    <input
                      ref="csrFileInput"
                      type="file"
                      class="d-none"
                      accept=".csr,.pem,.der"
                      @change="handleFileSelect"
                    />
                    <button
                      type="button"
                      class="btn btn-outline-primary"
                      @click="csrFileInput?.click()"
                    >
                      <i class="bi bi-folder2-open me-1"></i>
                      Browse Files
                    </button>
                  </div>

                  <!-- File Selected Display -->
                  <div v-else class="text-success">
                    <i class="bi bi-check-circle-fill text-success" style="font-size: 2rem;"></i>
                    <p class="mb-1 mt-2 fw-bold">{{ csrSignData.csr_file.name }}</p>
                    <p class="text-muted small mb-2">{{ formatFileSize(csrSignData.csr_file.size) }}</p>
                    <button
                      type="button"
                      class="btn btn-sm btn-outline-danger"
                      @click="clearCSRFile"
                    >
                      <i class="bi bi-x me-1"></i>
                      Remove File
                    </button>
                  </div>
                </div>

                <!-- Processing Status -->
                <div v-if="csrParsing" class="mt-3">
                  <div class="d-flex align-items-center">
                    <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                    Parsing CSR file...
                  </div>
                </div>
              </div>

              <!-- Parameters Section -->
              <div class="col-md-4">
                <h6 class="mb-3">Signing Parameters</h6>

                <div class="mb-3">
                  <label for="csrCaId" class="form-label">Certificate Authority</label>
                  <select
                      id="csrCaId"
                      v-model="csrSignData.ca_id"
                      class="form-select"
                      required
                  >
                    <option value="" disabled>Select a CA</option>
                    <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                      {{ ca.name }} ({{ ca.is_self_signed ? 'Self-Signed' : 'Imported' }})
                    </option>
                  </select>
                </div>

                <div class="mb-3">
                  <label for="csrUserId" class="form-label">Assign to User</label>
                  <select
                      id="csrUserId"
                      v-model="csrSignData.user_id"
                      class="form-control"
                      required
                  >
                    <option value="" disabled>Select a user</option>
                    <option v-for="user in userStore.users" :key="user.id" :value="user.id">
                      {{ user.name }}
                    </option>
                  </select>
                </div>

                <div class="mb-3">
                  <label for="csrValidity" class="form-label">Validity Period</label>
                  <select
                      id="csrValidity"
                      v-model="csrSignData.validity_in_days"
                      class="form-select"
                  >
                    <option :value="'365'">1 Year</option>
                    <option :value="'730'">2 Years</option>
                    <option :value="'1095'">3 Years</option>
                    <option :value="'1825'">5 Years</option>
                  </select>
                </div>

                <div class="mb-3">
                  <label for="csrCertType" class="form-label">Certificate Type</label>
                  <select
                      id="csrCertType"
                      v-model="csrSignData.certificate_type"
                      class="form-select"
                      required
                  >
                    <option value="client">Client Certificate</option>
                    <option value="server">Server Certificate</option>
                  </select>
                  <div v-if="isRootCA" class="form-text text-warning">
                    <i class="bi bi-exclamation-triangle me-1"></i>
                    Root CA mode: CSR signing restricted to client/server certificates only.
                  </div>
                </div>
              </div>
            </div>

            <!-- CSR Details Preview -->
            <div v-if="parsedCSRDetails" class="mt-4">
              <h6 class="mb-3">
                <i class="bi bi-info-circle me-2"></i>
                CSR Details Preview
              </h6>

              <div class="row">
                <!-- Subject Information -->
                <div class="col-md-6 mb-3">
                  <div class="card h-100">
                    <div class="card-header py-2">
                      <h6 class="mb-0 small">Subject Information</h6>
                    </div>
                    <div class="card-body py-2">
                      <div class="row g-1">
                        <div class="col-4 small text-muted">Common Name:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.commonName || 'N/A' }}</div>

                        <div class="col-4 small text-muted">Organization:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.organizationName || 'N/A' }}</div>

                        <div class="col-4 small text-muted">Org Unit:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.organizationalUnitName || 'N/A' }}</div>

                        <div class="col-4 small text-muted">Locality:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.localityName || 'N/A' }}</div>

                        <div class="col-4 small text-muted">State/Province:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.stateOrProvinceName || 'N/A' }}</div>

                        <div class="col-4 small text-muted">Country:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.countryName || 'N/A' }}</div>

                        <div class="col-4 small text-muted">Email:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.emailAddress || 'N/A' }}</div>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- Certificate Details -->
                <div class="col-md-6 mb-3">
                  <div class="card h-100">
                    <div class="card-header py-2">
                      <h6 class="mb-0 small">Certificate Details</h6>
                    </div>
                    <div class="card-body py-2">
                      <div class="row g-1">
                        <div class="col-4 small text-muted">Algorithm:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.algorithm || 'N/A' }}</div>

                        <div class="col-4 small text-muted">Key Size:</div>
                        <div class="col-8 small fw-mono">{{ parsedCSRDetails.keySize || 'N/A' }}</div>

                        <div class="col-4 small text-muted">Validates:</div>
                        <div class="col-8 small fw-mono">
                          {{ parsedCSRDetails.signatureValid ? 'Valid signature ✓' : 'Invalid signature ✗' }}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Subject Alternative Names -->
              <div v-if="parsedCSRDetails.subjectAltNames && parsedCSRDetails.subjectAltNames.length > 0" class="mb-3">
                <div class="card">
                  <div class="card-header py-2">
                    <h6 class="mb-0 small">Subject Alternative Names</h6>
                  </div>
                  <div class="card-body py-2">
                    <ul class="list-unstyled mb-0">
                      <li v-for="san in parsedCSRDetails.subjectAltNames" :key="san" class="small fw-mono">
                        {{ san }}
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            <!-- Error Messages -->
            <div v-if="csrError" class="alert alert-danger mt-3">
              <i class="bi bi-exclamation-triangle me-2"></i>
              {{ csrError }}
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeSignCSRModal">
              Cancel
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="!csrSignData.csr_file || !csrSignData.ca_id || !csrSignData.user_id || csrSigning"
                @click="signCSR"
            >
              <span v-if="csrSigning">
                <span class="spinner-border spinner-border-sm me-2" role="status"></span>
                Signing CSR...
              </span>
              <span v-else>
                <i class="bi bi-check-circle me-1"></i>
                Sign CSR & Create Certificate
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
</template>
<script setup lang="ts">
import {computed, onMounted, reactive, ref} from 'vue';
import {useCertificateStore} from '@/stores/certificates';
import {type Certificate, type CertificateDetails, CertificateRenewMethod, CertificateType} from "@/types/Certificate";
import type {CAAndCertificate} from "@/types/CA";
import {useAuthStore} from "@/stores/auth.ts";
import {useUserStore} from "@/stores/users.ts";
import {useSettingsStore} from "@/stores/settings.ts";
import {PasswordRule} from "@/types/Settings.ts";
import {fetchCAs, getCertificateDetails} from "@/api/certificates.ts";
import RevocationHistoryModal from "@/components/RevocationHistoryModal.vue";
import CertificateCreateModal from "@/components/CertificateCreateModal.vue";

// stores
const certificateStore = useCertificateStore();
const authStore = useAuthStore();
const userStore = useUserStore();
const settingStore = useSettingsStore();

// local state
const shownCerts = ref(new Set<number>());
const availableCAs = ref<CAAndCertificate[]>([]);

const certificates = computed(() => certificateStore.certificates);
const filteredCertificates = computed(() => {
  const allCerts = Array.from(certificates.value.values());

  switch (statusFilter.value) {
    case 'active':
      return allCerts.filter(cert => !cert.is_revoked && parseInt(cert.valid_until) > Date.now());
    case 'revoked':
      return allCerts.filter(cert => cert.is_revoked);
    case 'expired':
      return allCerts.filter(cert => !cert.is_revoked && parseInt(cert.valid_until) <= Date.now());
    case 'all':
    default:
      return allCerts;
  }
});
const settings = computed(() => settingStore.settings);
const loading = computed(() => certificateStore.loading);
const error = computed(() => certificateStore.error);

const isDeleteModalVisible = ref(false);
const isGenerateModalVisible = ref(false);
const isCertificateDetailsModalVisible = ref(false);
const isRevokeModalVisible = ref(false);
const certToDelete = ref<Certificate | null>(null);
const certToRevoke = ref<Certificate | null>(null);

// Modal state for download format selection
const showDownloadModal = ref(false);
const downloadCertificateRef = ref<{id: number, name: string} | null>(null);
const selectedFormat = ref<string>('pkcs12');

// Revocation modal state
const revocationReason = ref<number>(0);
const customRevocationReason = ref<string>('');
const notifyUserOnRevoke = ref<boolean>(false);

// Filter state
const statusFilter = ref<string>('all');

// Bulk selection state
const selectedCertificates = ref(new Set<number>());
const selectableCertificates = computed(() => {
  return filteredCertificates.value.filter(cert => !cert.is_revoked);
});

// Revocation history modal state
const showRevocationHistory = ref(false);

// Advanced configuration collapse state

// CSR Signing modal state
const showSignCSRModal = ref(false);

// CSR signing form data
const csrSignData = reactive({
  csr_file: null as File | null,
  cert_name: '',
  ca_id: '',
  user_id: '',
  certificate_type: 'client' as 'client' | 'server',
  validity_in_days: '365',
});

const certificateDetails = ref<CertificateDetails | null>(null);

const passwordRule = computed(() => {
  return settings.value?.common.password_rule ?? PasswordRule.Optional;
});

const isMailValid = computed(() => {
  return (settings.value?.mail.smtp_host.length ?? 0) > 0 && (settings.value?.mail.smtp_port ?? 0) > 0;
});

const isRootCA = computed(() => {
  return settings.value?.common.is_root_ca ?? false;
});


const isRevokeValid = computed(() => {
  return true; // All RFC 5280 reasons are now predefined and valid
});



onMounted(async () => {
  await certificateStore.fetchCertificates();
  await settingStore.fetchSettings();
  if (authStore.isAdmin) {
    await userStore.fetchUsers();
  }
});

const onCertificateCreated = () => {
  // Refresh the certificate list after creation
  certificateStore.fetchCertificates();
};

const fetchAvailableCAs = async () => {
  try {
    availableCAs.value = await fetchCAs();
  } catch (err) {
    console.error('Failed to fetch CAs:', err);
  }
};

const openGenerateModal = async () => {
  await fetchAvailableCAs();
  isGenerateModalVisible.value = true;
};


const confirmDeletion = (cert: Certificate) => {
  // Check if certificate is revoked
  if (cert.is_revoked) {
    alert('Cannot delete revoked certificate. Revoked certificates cannot be deleted to maintain audit trail integrity.');
    return;
  }

  certToDelete.value = cert;
  isDeleteModalVisible.value = true;
};

const closeDeleteModal = () => {
  certToDelete.value = null;
  isDeleteModalVisible.value = false;
};

const handleDownload = (certificate: {id: number, name: string}) => {
  downloadCertificateRef.value = certificate;
  selectedFormat.value = 'pkcs12';
  showDownloadModal.value = true;
};

const confirmDownload = async () => {
  if (!downloadCertificateRef.value) return;

  try {
    await certificateStore.downloadCertificate(
      downloadCertificateRef.value.id,
      selectedFormat.value
    );
    showDownloadModal.value = false;
    downloadCertificateRef.value = null;
  } catch (error) {
    console.error('Failed to download certificate:', error);
  }
};

const deleteCertificate = async () => {
  if (certToDelete.value) {
    await certificateStore.deleteCertificate(certToDelete.value.id);
    closeDeleteModal();
  }
};

const confirmRevocation = (cert: Certificate | CertificateDetails) => {
  // Convert CertificateDetails to Certificate format if needed
  if ('pkcs12_password' in cert) {
    certToRevoke.value = cert;
  } else {
    // Convert CertificateDetails to Certificate format
    certToRevoke.value = {
      id: cert.id,
      name: cert.name,
      created_on: cert.created_on.toString(),
      pkcs12_password: '', // Will be fetched if needed
      valid_until: cert.valid_until.toString(),
      certificate_type: cert.certificate_type,
      user_id: cert.user_id,
      renew_method: cert.renew_method,
      is_revoked: cert.is_revoked,
      revoked_on: cert.revoked_on,
      revoked_reason: cert.revoked_reason,
      revoked_by: cert.revoked_by
    };
  }
  revocationReason.value = 0; // Default to "Unspecified"
  notifyUserOnRevoke.value = false;
  isRevokeModalVisible.value = true;
};

const closeRevokeModal = () => {
  certToRevoke.value = null;
  isRevokeModalVisible.value = false;
  revocationReason.value = 0;
  customRevocationReason.value = '';
  notifyUserOnRevoke.value = false;
};

const revokeCertificate = async () => {
  // Handle bulk revocation
  if (selectedCertificates.value.size > 0) {
    try {
      const revokePromises = Array.from(selectedCertificates.value).map(certId =>
        certificateStore.revokeCertificate(certId, revocationReason.value, notifyUserOnRevoke.value)
      );

      await Promise.all(revokePromises);
      selectedCertificates.value.clear(); // Clear selection after successful bulk revocation
      closeRevokeModal();
    } catch (error) {
      console.error('Failed to revoke certificates:', error);
      alert('Failed to revoke some certificates. Please try again.');
    }
    return;
  }

  // Handle single certificate revocation
  if (!certToRevoke.value) return;

  try {
    await certificateStore.revokeCertificate(
      certToRevoke.value.id,
      revocationReason.value,
      notifyUserOnRevoke.value
    );
    closeRevokeModal();
  } catch (error) {
    console.error('Failed to revoke certificate:', error);
    alert('Failed to revoke certificate. Please try again.');
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

const getCertificateStatusText = (cert: Certificate): string => {
  // Check revocation first
  if (cert.is_revoked) {
    return 'Revoked';
  }

  const now = Date.now();
  const validUntil = parseInt(cert.valid_until);

  if (validUntil < now) {
    return 'Expired';
  } else if (validUntil < now + (30 * 24 * 60 * 60 * 1000)) { // 30 days
    return 'Expiring Soon';
  } else {
    return 'Active';
  }
};

const getCertificateStatusClass = (cert: Certificate): string => {
  const status = getCertificateStatusText(cert);
  switch (status) {
    case 'Revoked':
      return 'bg-dark';
    case 'Expired':
      return 'bg-danger';
    case 'Expiring Soon':
      return 'bg-warning text-dark';
    case 'Active':
      return 'bg-success';
    default:
      return 'bg-secondary';
  }
};

const getCertificateStatusTooltip = (cert: Certificate): string => {
  if (cert.is_revoked) {
    const reason = getRevocationReasonText(cert.revoked_reason || 0);
    return `Certificate revoked on ${new Date(cert.revoked_on || 0).toLocaleDateString()} - Reason: ${reason}`;
  }

  const now = Date.now();
  const validUntil = parseInt(cert.valid_until);

  if (validUntil < now) {
    const daysExpired = Math.floor((now - validUntil) / (24 * 60 * 60 * 1000));
    return `Certificate expired ${daysExpired} days ago`;
  } else if (validUntil < now + (30 * 24 * 60 * 60 * 1000)) {
    const daysLeft = Math.floor((validUntil - now) / (24 * 60 * 60 * 1000));
    return `Certificate expires in ${daysLeft} days - renewal recommended`;
  } else {
    return `Certificate is valid and active`;
  }
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

const copyPasswordToClipboard = async (cert: Certificate) => {
  try {
    // First ensure the password is loaded
    if (!cert.pkcs12_password) {
      await certificateStore.fetchCertificatePassword(cert.id);
      // Get the updated certificate from the store
      const updatedCert = certificates.value.get(cert.id);
      if (updatedCert?.pkcs12_password) {
        await navigator.clipboard.writeText(updatedCert.pkcs12_password);
      }
    } else {
      await navigator.clipboard.writeText(cert.pkcs12_password);
    }

    // Show temporary feedback on the button
    const btn = event?.target as HTMLElement;
    if (btn) {
      const originalContent = btn.innerHTML;
      btn.innerHTML = '<i class="bi bi-check me-1"></i>Copied!';
      setTimeout(() => btn.innerHTML = originalContent, 2000);
    }
  } catch (err) {
    console.error('Failed to copy password to clipboard:', err);
    // Fallback for older browsers
    const password = cert.pkcs12_password || certificates.value.get(cert.id)?.pkcs12_password;
    if (password) {
      const textArea = document.createElement('textarea');
      textArea.value = password;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    }
  }
};

// Bulk selection functions
const toggleCertificateSelection = (certId: number) => {
  if (selectedCertificates.value.has(certId)) {
    selectedCertificates.value.delete(certId);
  } else {
    selectedCertificates.value.add(certId);
  }
};

const toggleSelectAll = () => {
  const allSelected = selectedCertificates.value.size === selectableCertificates.value.length;
  if (allSelected) {
    // Deselect all
    selectedCertificates.value.clear();
  } else {
    // Select all selectable certificates
    selectedCertificates.value.clear();
    selectableCertificates.value.forEach(cert => {
      selectedCertificates.value.add(cert.id);
    });
  }
};

const clearSelection = () => {
  selectedCertificates.value.clear();
};

const confirmBulkRevocation = () => {
  if (selectedCertificates.value.size === 0) return;

  // Set up bulk revocation modal
  certToRevoke.value = null; // Clear individual cert
  revocationReason.value = 0; // Default to "Unspecified"
  notifyUserOnRevoke.value = false;
  isRevokeModalVisible.value = true;
};

// CSR Signing modal states
const parsedCSRDetails = ref<{
  commonName?: string;
  organizationName?: string;
  organizationalUnitName?: string;
  localityName?: string;
  stateOrProvinceName?: string;
  emailAddress?: string;
  countryName?: string;
  algorithm?: string;
  keySize?: string;
  signatureValid?: boolean;
  subjectAltNames?: string[];
} | null>(null);

const csrParsing = ref(false);
const csrError = ref('');
const csrSigning = ref(false);
const csrFileInput = ref<HTMLInputElement | null>(null);

// CSR modal functions
const showSignCSRModalFunction = async () => {
  await userStore.fetchUsers();
  await fetchAvailableCAs();
  showSignCSRModal.value = true;
};

const closeSignCSRModal = () => {
  showSignCSRModal.value = false;
  clearCSRForm();
};

const clearCSRForm = () => {
  csrSignData.csr_file = null;
  csrSignData.cert_name = '';
  csrSignData.ca_id = '';
  csrSignData.user_id = '';
  csrSignData.certificate_type = 'client';
  csrSignData.validity_in_days = '365';
  parsedCSRDetails.value = null;
  csrError.value = '';
  csrParsing.value = false;
  csrSigning.value = false;
};

const handleDragOver = (event: DragEvent) => {
  if (event.dataTransfer) {
    event.dataTransfer.dropEffect = 'copy';
  }
};

const handleDragLeave = () => {
  // Visual feedback handled by CSS
};

const handleFileDrop = (event: DragEvent) => {
  const files = event.dataTransfer?.files;
  if (files && files.length > 0) {
    handleCSRFile(files[0]);
  }
};

const handleFileSelect = (event: Event) => {
  const target = event.target as HTMLInputElement;
  const files = target.files;
  if (files && files.length > 0) {
    handleCSRFile(files[0]);
  }
};

const handleCSRFile = async (file: File) => {
  // Basic validation
  if (!file) return;

  // Check file size (100KB limit)
  if (file.size > 100 * 1024) {
    csrError.value = 'File size exceeds 100KB limit.';
    return;
  }

  // Check file extension
  const ext = file.name.toLowerCase().split('.').pop();
  if (!['csr', 'pem', 'der'].includes(ext || '')) {
    csrError.value = 'Invalid file format. Only .csr, .pem, and .der files are allowed.';
    return;
  }

  // Set file and clear errors
  csrSignData.csr_file = file;
  csrError.value = '';

  // Parse CSR for preview
  await parseCSRFile(file);
};

const parseCSRFile = async (file: File) => {
  csrParsing.value = true;
  csrError.value = '';
  parsedCSRDetails.value = null;

  try {
    const formData = new FormData();
    formData.append('csr_file', file);

    const response = await certificateStore.previewCsr(formData);
    

    // Map backend response to frontend format
    parsedCSRDetails.value = {
      commonName: response.common_name,
      organizationName: response.organization_name,
      organizationalUnitName: response.organizational_unit_name,
      localityName: response.locality_name,
      stateOrProvinceName: response.state_or_province_name,
      emailAddress: response.email_address,
      countryName: response.country_name,
      algorithm: response.algorithm,
      keySize: response.key_size,
      signatureValid: response.signature_valid,
      subjectAltNames: response.subject_alt_names
    };
    console.log('CSR preview response:', parsedCSRDetails.value);

  } catch (error) {
    console.error('Failed to parse CSR:', error);
    csrError.value = 'Failed to parse CSR file. Please ensure it is a valid certificate signing request.';
    parsedCSRDetails.value = null;
  } finally {
    csrParsing.value = false;
  }
};

const clearCSRFile = () => {
  csrSignData.csr_file = null;
  parsedCSRDetails.value = null;
  csrError.value = '';
};

const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const signCSR = async () => {
  if (!csrSignData.csr_file || !csrSignData.ca_id || !csrSignData.user_id) {
    csrError.value = 'Please select a CSR file, CA, and user.';
    return;
  }

  csrSigning.value = true;
  csrError.value = '';

  try {
    const formData = new FormData();
    formData.append('csr_file', csrSignData.csr_file);
    formData.append('cert_name', csrSignData.cert_name || parsedCSRDetails.value?.commonName || 'CSR-Certificate');
    formData.append('ca_id', csrSignData.ca_id);
    formData.append('user_id', csrSignData.user_id);
    formData.append('certificate_type', csrSignData.certificate_type);
    formData.append('validity_in_days', csrSignData.validity_in_days);

    await certificateStore.signCsrCertificate(formData);

    // Show success and refresh certificates
    await certificateStore.fetchCertificates();
    closeSignCSRModal();

    // Optional: Show success notification here

  } catch (error) {
    console.error('Failed to sign CSR:', error);
    csrError.value = 'Failed to sign certificate. Please try again.';
  } finally {
    csrSigning.value = false;
  }
};

// Expose the show function (since component uses showSignCSRModal but function is named showSignCSRModalFunction)
</script>


<style scoped>
.overview-container {
  background-color: transparent;
}

@media (max-width: 768px) {
  .overview-container {
    padding: 0;
  }
}
</style>
