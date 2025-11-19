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
            @click="showGenerateModal"
        >
          {{ isRootCA ? 'Create Subordinate CA' : 'Create New Certificate' }}
        </button>
        <button
            v-if="authStore.isAdmin"
            class="btn btn-outline-secondary"
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
        <div class="table-responsive">
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
                    <img
                        :id="'PasswordButton-' + cert.id"
                        :src="shownCerts.has(cert.id) ? '/images/eye-open.png' : '/images/eye-hidden.png'"
                        class="ms-2"
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
      <div class="modal-dialog modal-xl">
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
                <option v-if="!isRootCA" :value="CertificateType.Client">Client</option>
                <option v-if="!isRootCA" :value="CertificateType.Server">Server</option>
                <option v-if="isRootCA" :value="CertificateType.SubordinateCA">Subordinate CA</option>
              </select>
              <div v-if="isRootCA" class="form-text text-info">
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
                <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
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
                type="button"
                class="btn btn-outline-secondary btn-sm"
                @click="advancedConfigExpanded = !advancedConfigExpanded"
              >
                <i :class="advancedConfigExpanded ? 'bi bi-chevron-up' : 'bi bi-chevron-down'"></i>
                Advanced Certificate Configuration
                <!-- <small class="text-muted ms-1">(Key Type, Key Size, Hash Algorithm, URLs)</small> -->
              </button>
            </div>

            <div v-if="advancedConfigExpanded" class="border rounded p-3 mb-3 bg-light">
              <!-- Cryptographic Parameters -->
              <h6 class="mb-3">Cryptographic Parameters</h6>
              <div class="mb-3">
                <label class="form-label">Key Type</label>
                <div class="form-check">
                  <input
                    class="form-check-input"
                    type="radio"
                    id="keyTypeRSA-overview"
                    value="RSA"
                    v-model="certReq.key_type"
                    required
                  >
                  <label class="form-check-label" for="keyTypeRSA-overview">
                    RSA
                  </label>
                </div>
                <div class="form-check">
                  <input
                    class="form-check-input"
                    type="radio"
                    id="keyTypeECDSA-overview"
                    value="ECDSA"
                    v-model="certReq.key_type"
                    required
                  >
                  <label class="form-check-label" for="keyTypeECDSA-overview">
                    ECDSA
                  </label>
                </div>
              </div>

              <div class="row mb-3">
                <div class="col-md-6">
                  <label for="keySize-overview" class="form-label">Key Size</label>
                  <select
                    class="form-select"
                    id="keySize-overview"
                    v-model="certReq.key_size"
                    required
                  >
                    <option v-if="certReq.key_type === 'RSA'" value="2048">2048</option>
                    <option v-if="certReq.key_type === 'RSA'" value="4096">4096</option>
                    <option v-if="certReq.key_type === 'ECDSA'" value="P-256">P-256</option>
                    <option v-if="certReq.key_type === 'ECDSA'" value="P-521">P-521</option>
                  </select>
                </div>
                <div class="col-md-6">
                  <label for="hashAlgorithm-overview" class="form-label">Hash Algorithm</label>
                  <select
                    class="form-select"
                    id="hashAlgorithm-overview"
                    v-model="certReq.hash_algorithm"
                    required
                  >
                    <option value="sha256">SHA-256</option>
                    <option value="sha512">SHA-512</option>
                  </select>
                </div>
              </div>

              <!-- Certificate URLs -->
              <h6 class="mb-3">Certificate Extensions URLs</h6>
              <div class="row">
                <div class="col-md-6 mb-3">
                  <label for="aiaUrl-overview" class="form-label">AIA URL (Authority Information Access)</label>
                  <input
                    type="url"
                    class="form-control"
                    id="aiaUrl-overview"
                    v-model="certReq.aia_url"
                    placeholder="https://your-ca.example.com/certs/ca.cert.pem"
                    :title="certReq.aia_url ? 'Custom AIA URL' : 'Will inherit from selected CA'"
                  />
                  <small class="text-muted">
                    URL where the CA certificate can be downloaded for client validation.
                    <strong v-if="!certReq.aia_url">Default: inherited from CA</strong>
                  </small>
                </div>
                <div class="col-md-6 mb-3">
                  <label for="cdpUrl-overview" class="form-label">CDP URL (Certificate Revocation List)</label>
                  <input
                    type="url"
                    class="form-control"
                    id="cdpUrl-overview"
                    v-model="certReq.cdp_url"
                    placeholder="https://your-ca.example.com/crl/ca.crl.pem"
                    :title="certReq.cdp_url ? 'Custom CDP URL' : 'Will inherit from selected CA'"
                  />
                  <small class="text-muted">
                    URL where the Certificate Revocation List can be downloaded.
                    <strong v-if="!certReq.cdp_url">Default: inherited from CA</strong>
                  </small>
                </div>
              </div>

              <div class="alert alert-info">
                <i class="bi bi-info-circle me-2"></i>
                These settings configure the cryptographic parameters and certificate extensions for this certificate.
                By default, these values match your selected CA's parameters and URLs.
              </div>
            </div>
            <div class="mb-3" v-if="certReq.cert_type == CertificateType.Server">
              <label class="form-label">DNS Names</label>
              <div v-for="(_, index) in certReq.dns_names" :key="index" class="mb-2">
                <div class="input-group">
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
                :disabled="loading || (passwordRule == PasswordRule.Required && !certReq.system_generated_password && certReq.pkcs12_password.length == 0)"
                @click="createCertificate"
            >
              <span v-if="loading">Creating...</span>
              <span v-else>Create Certificate</span>
            </button>
          </div>
        </div>
      </div>
    </div>

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
                  title="Choose the appropriate revocation reason"
              >
                <option :value="0" title="No specific reason given">Unspecified</option>
                <option :value="1" title="Certificate is temporarily suspended">Certificate Hold</option>
                <option :value="2" title="Custom reason will be provided">Specify</option>
              </select>
            </div>
            <div v-if="revocationReason === 2" class="mb-3">
              <label for="customRevocationReason" class="form-label">Custom Reason</label>
              <textarea
                  id="customRevocationReason"
                  v-model="customRevocationReason"
                  class="form-control"
                  placeholder="Please provide a custom reason for revocation"
                  rows="3"
                  maxlength="500"
              ></textarea>
              <div class="form-text">
                Provide a detailed reason for revoking this certificate (maximum 500 characters).
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
          <div class="modal-footer">
            <button
                v-if="authStore.isAdmin && certificateDetails && !certificateDetails.is_revoked"
                type="button"
                class="btn btn-warning me-auto"
                @click="confirmRevocation(certificateDetails)"
            >
              <i class="bi bi-x-circle me-1"></i>
              Revoke Certificate
            </button>
            <button type="button" class="btn btn-secondary" @click="closeCertificateDetailsModal">Close</button>
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
import RevocationHistoryModal from "@/components/RevocationHistoryModal.vue";

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
const advancedConfigExpanded = ref(false);

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
  key_type: 'RSA',
  key_size: '2048',
  hash_algorithm: 'sha256',
  aia_url: '',
  cdp_url: '',
});

const isMailValid = computed(() => {
  return (settings.value?.mail.smtp_host.length ?? 0) > 0 && (settings.value?.mail.smtp_port ?? 0) > 0;
});

const selectedCA = computed(() => {
  return availableCAs.value.find(ca => ca.id === certReq.ca_id);
});

const isRootCA = computed(() => {
  return settings.value?.common.is_root_ca ?? false;
});

const isRevokeValid = computed(() => {
  if (revocationReason.value === 2) {
    return customRevocationReason.value.trim().length > 0;
  }
  return true;
});

// Watch for Root CA mode changes and set certificate type to Subordinate CA
watch(isRootCA, (newIsRootCA: boolean) => {
  if (newIsRootCA) {
    certReq.cert_type = CertificateType.SubordinateCA;
  } else {
    // Reset to Client when not in Root CA mode
    certReq.cert_type = CertificateType.Client;
  }
}, { immediate: true });

watch(passwordRule, (newVal) => {
  certReq.system_generated_password = (newVal === PasswordRule.System);
}, { immediate: true });

// Watch for key type changes and reset key size to appropriate default
watch(() => certReq.key_type, (newKeyType: string | undefined) => {
  if (newKeyType === 'RSA' && certReq.key_size !== '2048' && certReq.key_size !== '4096') {
    certReq.key_size = '2048';
  } else if (newKeyType === 'ECDSA' && certReq.key_size !== 'P-256' && certReq.key_size !== 'P-521') {
    certReq.key_size = 'P-256';
  }
});

// Watch for selected CA changes and set defaults to match CA's parameters
watch(selectedCA, (newSelectedCA: CAAndCertificate | undefined) => {
  if (newSelectedCA) {
    // Set defaults to match the selected CA's cryptographic parameters
    const keySizeStr = newSelectedCA.key_size;
    const sigAlgStr = newSelectedCA.signature_algorithm;

    // Determine key type from signature algorithm or key size
    if (sigAlgStr.includes('RSA') || keySizeStr.startsWith('2048') || keySizeStr.startsWith('4096')) {
      certReq.key_type = 'RSA';
      // Extract just the number from key size (e.g., "RSA 2048" -> "2048")
      const rsaSize = keySizeStr.match(/(\d+)/)?.[1];
      certReq.key_size = rsaSize && ['2048', '4096'].includes(rsaSize) ? rsaSize : '2048';
    } else if (sigAlgStr.includes('ECDSA') || keySizeStr.includes('P-256') || keySizeStr.includes('P-521')) {
      certReq.key_type = 'ECDSA';
      // Extract curve from key size (e.g., "ECDSA P-256" -> "P-256")
      if (keySizeStr.includes('P-256')) {
        certReq.key_size = 'P-256';
      } else if (keySizeStr.includes('P-521')) {
        certReq.key_size = 'P-521';
      } else {
        certReq.key_size = 'P-256';
      }
    }

    // Determine hash algorithm from signature algorithm
    if (sigAlgStr.includes('SHA512') || sigAlgStr.includes('sha512')) {
      certReq.hash_algorithm = 'sha512';
    } else if (sigAlgStr.includes('SHA256') || sigAlgStr.includes('sha256')) {
      certReq.hash_algorithm = 'sha256';
    }

    // Set AIA and CDP URLs from the selected CA (can be overridden by user)
    certReq.aia_url = newSelectedCA.aia_url || '';
    certReq.cdp_url = newSelectedCA.cdp_url || '';
  }
});

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
  certReq.aia_url = '';
  certReq.cdp_url = '';
};

const createCertificate = async () => {
    await certificateStore.createCertificate(certReq);
    closeGenerateModal();
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
        certificateStore.revokeCertificate(certId, revocationReason.value, notifyUserOnRevoke.value, revocationReason.value === 2 ? customRevocationReason.value : undefined)
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
      notifyUserOnRevoke.value,
      revocationReason.value === 2 ? customRevocationReason.value : undefined
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

.table-responsive {
  border-radius: var(--radius-md);
  overflow: hidden;
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
