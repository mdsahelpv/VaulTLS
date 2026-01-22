<template>
  <div class="ca-tools-container">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2 class="mb-0">
        CA Tools
      </h2>
      <button
        class="btn btn-primary"
        @click="handleAddCA"
      >
        <i class="bi bi-plus-circle me-2" />
        {{ isRootCA ? 'Add Root CA' : 'Add CA' }}
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
        Loading CAs...
      </p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error"
      class="alert alert-danger"
    >
      <i class="bi bi-exclamation-triangle me-2" />
      {{ error }}
      <button
        class="btn btn-sm btn-outline-danger ms-3"
        @click="loadCAs"
      >
        Retry
      </button>
    </div>

    <!-- CA List -->
    <div
      v-else-if="cas && cas.length > 0"
      class="card"
    >
      <div class="card-header">
        <h5 class="mb-0">
          <i class="bi bi-shield-check me-2" />
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
                <th class="text-center">
                  Actions
                </th>
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
                  <span
                    class="badge"
                    :class="getCATypeText(ca) === 'Self-Signed' ? 'bg-success' : 'bg-info'"
                  >
                    {{ getCATypeText(ca) }}
                  </span>
                </td>
                <td>
                  <span
                    class="badge"
                    :class="getStatusClass(ca)"
                  >
                    {{ getStatusText(ca) }}
                  </span>
                </td>
                <td>{{ formatDate(ca.created_on) }}</td>
                <td>{{ formatDate(ca.valid_until) }}</td>
                <td>
                  <div class="d-flex flex-sm-row flex-column gap-1">
                    <button
                      class="btn btn-primary btn-sm"
                      title="View CA Details"
                      @click="viewCADetails(ca)"
                    >
                      <i class="bi bi-eye" /> View
                    </button>
                    <button
                      class="btn btn-primary btn-sm"
                      title="Download CA Certificate and Private Key"
                      @click="handleDownloadCAKeyPair(ca)"
                    >
                      <i class="bi bi-eye" /> Download
                    </button>
                    <button
                      v-if="isAdmin"
                      class="btn btn-danger btn-sm flex-grow-1"
                      title="Delete CA"
                      @click="confirmDeleteCA(ca)"
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
    <div
      v-else
      class="text-center py-5"
    >
      <i
        class="bi bi-shield-slash text-muted"
        style="font-size: 3rem;"
      />
      <h4 class="mt-3">
        No Certificate Authorities Found
      </h4>
      <p class="text-muted">
        Create your first CA to start managing certificates.
      </p>
      <button
        class="btn btn-primary"
        @click="handleAddCA"
      >
        <i class="bi bi-plus-circle me-2" />
        {{ isRootCA ? 'Create Your First Root CA' : 'Create Your First CA' }}
      </button>
    </div>

    <!-- Add CA Modal -->
    <div
      class="modal fade"
      :class="{ show: showAddCAModal }"
      :style="{ display: showAddCAModal ? 'block' : 'none' }"
      tabindex="-1"
    >
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">
              {{ isRootCA ? 'Create Root CA' : 'Import Subordinate Certificate Authority' }}
            </h5>
            <button
              type="button"
              class="btn-close"
              @click="showAddCAModal = false"
            />
          </div>
          <div class="modal-body">
            <!-- Self-Signed CA Form -->
            <div
              v-if="caCreationType === 'self-signed'"
              class="mt-4"
            >
              <form @submit.prevent="createSelfSignedCAWrapper">
                <!-- Distinguished Name Fields -->
                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label
                      for="countryName"
                      class="form-label"
                    >Country Name (2 letter code)</label>
                    <input
                      id="countryName"
                      v-model="selfSignedForm.countryName"
                      type="text"
                      class="form-control"
                      required
                      maxlength="2"
                      placeholder="QA"
                    >
                  </div>
                  <div class="col-md-6 mb-3">
                    <label
                      for="stateOrProvinceName"
                      class="form-label"
                    >State or Province Name</label>
                    <input
                      id="stateOrProvinceName"
                      v-model="selfSignedForm.stateOrProvinceName"
                      type="text"
                      class="form-control"
                      required
                      placeholder="Doha"
                    >
                  </div>
                </div>

                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label
                      for="localityName"
                      class="form-label"
                    >Locality Name</label>
                    <input
                      id="localityName"
                      v-model="selfSignedForm.localityName"
                      type="text"
                      class="form-control"
                      required
                      placeholder="Bin Omran"
                    >
                  </div>
                  <div class="col-md-6 mb-3">
                    <label
                      for="organizationName"
                      class="form-label"
                    >Organization Name</label>
                    <input
                      id="organizationName"
                      v-model="selfSignedForm.organizationName"
                      type="text"
                      class="form-control"
                      required
                      placeholder="Your Organization"
                    >
                  </div>
                </div>

                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label
                      for="organizationalUnitName"
                      class="form-label"
                    >Organizational Unit (Optional)</label>
                    <input
                      id="organizationalUnitName"
                      v-model="selfSignedForm.organizationalUnitName"
                      type="text"
                      class="form-control"
                      placeholder="IT Department"
                    >
                  </div>
                  <div class="col-md-6 mb-3">
                    <label
                      for="commonName"
                      class="form-label"
                    >Common Name</label>
                    <input
                      id="commonName"
                      v-model="selfSignedForm.commonName"
                      type="text"
                      class="form-control"
                      required
                      placeholder="rootca.yourdomain.com"
                    >
                  </div>
                </div>

                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label
                      for="emailAddress"
                      class="form-label"
                    >Email Address</label>
                    <input
                      id="emailAddress"
                      v-model="selfSignedForm.emailAddress"
                      type="email"
                      class="form-control"
                      required
                      placeholder="pki@yourdomain.com"
                    >
                  </div>
                  <div class="col-md-6 mb-3">
                    <label
                      for="ca_validity_in_years"
                      class="form-label"
                    >Validity (Years)</label>
                    <input
                      id="ca_validity_in_years"
                      v-model.number="selfSignedForm.validityYears"
                      type="number"
                      class="form-control"
                      required
                      min="1"
                      max="30"
                    >
                  </div>
                </div>

                <div class="mb-3">
                  <label
                    for="ca_name"
                    class="form-label"
                  >CA Display Name (Optional)</label>
                  <input
                    id="ca_name"
                    v-model="selfSignedForm.caName"
                    type="text"
                    class="form-control"
                    placeholder="Defaults to Common Name if left empty"
                  >
                  <small class="text-muted">Optional display name for the CA. If left empty, the Common Name will be used.</small>
                </div>

                <!-- Advanced CA Configuration -->
                <h6 class="mb-3 mt-4">
                  Advanced CA Configuration
                </h6>

                <div class="mb-3">
                  <label class="form-label">Key Type</label>
                  <div class="form-check">
                    <input
                      id="keyTypeRSA"
                      v-model="selfSignedForm.keyType"
                      class="form-check-input"
                      type="radio"
                      value="RSA"
                      required
                    >
                    <label
                      class="form-check-label"
                      for="keyTypeRSA"
                    >
                      RSA
                    </label>
                  </div>
                  <div class="form-check">
                    <input
                      id="keyTypeECDSA"
                      v-model="selfSignedForm.keyType"
                      class="form-check-input"
                      type="radio"
                      value="ECDSA"
                      required
                    >
                    <label
                      class="form-check-label"
                      for="keyTypeECDSA"
                    >
                      ECDSA
                    </label>
                  </div>
                </div>

                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label
                      for="keySize"
                      class="form-label"
                    >Key Size</label>
                    <select
                      id="keySize"
                      v-model="selfSignedForm.keySize"
                      class="form-select"
                      required
                    >
                      <option
                        v-if="selfSignedForm.keyType === 'RSA'"
                        value="2048"
                      >
                        2048
                      </option>
                      <option
                        v-if="selfSignedForm.keyType === 'RSA'"
                        value="4096"
                      >
                        4096
                      </option>
                      <option
                        v-if="selfSignedForm.keyType === 'ECDSA'"
                        value="P-256"
                      >
                        P-256
                      </option>
                      <option
                        v-if="selfSignedForm.keyType === 'ECDSA'"
                        value="P-521"
                      >
                        P-521
                      </option>
                    </select>
                  </div>
                  <div class="col-md-6 mb-3">
                    <label
                      for="hashAlgorithm"
                      class="form-label"
                    >Hash Algorithm</label>
                    <select
                      id="hashAlgorithm"
                      v-model="selfSignedForm.hashAlgorithm"
                      class="form-select"
                      required
                    >
                      <option value="sha256">
                        SHA-256
                      </option>
                      <option value="sha512">
                        SHA-512
                      </option>
                    </select>
                  </div>
                </div>

                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label
                      for="crlValidityDays"
                      class="form-label"
                    >CRL Validity (days)</label>
                    <input
                      id="crlValidityDays"
                      v-model.number="selfSignedForm.crlValidityDays"
                      type="number"
                      class="form-control"
                      required
                      min="1"
                      max="365"
                    >
                  </div>
                  <div class="col-md-6 mb-3">
                    <label
                      for="pathLength"
                      class="form-label"
                    >Maximum intermediate CA levels</label>
                    <input
                      id="pathLength"
                      v-model.number="selfSignedForm.pathLength"
                      type="number"
                      class="form-control"
                      required
                      min="0"
                      max="10"
                    >
                  </div>
                </div>

                <div class="mb-3">
                  <label
                    for="aiaUrl"
                    class="form-label"
                  >AIA URL (where CA certificate can be downloaded)</label>
                  <input
                    id="aiaUrl"
                    v-model="selfSignedForm.aiaUrl"
                    type="url"
                    class="form-control"
                    placeholder="https://pki.example.com/certs/ca.cert.pem"
                  >
                </div>

                <div class="mb-3">
                  <label
                    for="cdpUrl"
                    class="form-label"
                  >CDP URL (where Certificate Revocation List can be downloaded)</label>
                  <input
                    id="cdpUrl"
                    v-model="selfSignedForm.cdpUrl"
                    type="url"
                    class="form-control"
                    placeholder="https://pki.example.com/crl/ca.crl.pem"
                  >
                </div>

                <div class="alert alert-info">
                  <i class="bi bi-info-circle me-2" />
                  {{ isRootCA ? 'These settings configure the Distinguished Name (DN) and advanced certificate extensions for your subordinate CA certificate, following standard X.509 certificate practices.' : 'These settings configure the Distinguished Name (DN) and advanced certificate extensions for your Root CA certificate, following standard X.509 certificate practices. Default values are loaded from the OpenSSL configuration.' }}
                </div>

                <div class="d-flex gap-2">
                  <button
                    type="submit"
                    class="btn btn-primary"
                    :disabled="creatingCA"
                  >
                    <span
                      v-if="creatingCA"
                      class="spinner-border spinner-border-sm me-2"
                      role="status"
                    />
                    {{ isRootCA ? 'Create Subordinate CA' : 'Create Root CA' }}
                  </button>
                  <button
                    type="button"
                    class="btn btn-secondary"
                    @click="showAddCAModal = false"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>

            <!-- Import CA Form -->
            <div
              v-if="caCreationType === 'import'"
              class="mt-4"
            >
              <form @submit.prevent="importCA">
                <div class="mb-3">
                  <label
                    for="pkcs12File"
                    class="form-label"
                  >Upload your existing CA certificate in PKCS#12 format</label>
                  <input
                    id="pkcs12File"
                    ref="fileInput"
                    type="file"
                    class="form-control"
                    accept=".p12,.pfx"
                    required
                    @change="handleFileSelect"
                  >
                </div>
                <div class="mb-3">
                  <label
                    for="importPassword"
                    class="form-label"
                  >PKCS#12 Password</label>
                  <input
                    id="importPassword"
                    v-model="importForm.password"
                    type="password"
                    class="form-control"
                    placeholder="Leave empty if no password is set"
                  >
                </div>
                <div class="alert alert-info">
                  <i class="bi bi-info-circle me-2" />
                  The PKCS#12 file should contain the CA certificate, private key, and any intermediate certificates.
                </div>
                <div class="d-flex gap-2">
                  <button
                    type="submit"
                    class="btn btn-success"
                    :disabled="creatingCA || !importForm.file"
                  >
                    <span
                      v-if="creatingCA"
                      class="spinner-border spinner-border-sm me-2"
                      role="status"
                    />
                    Import CA
                  </button>
                  <button
                    type="button"
                    class="btn btn-secondary"
                    @click="showAddCAModal = false"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- CA Details Modal -->
    <div
      class="modal fade"
      :class="{ show: showCADetailsModal }"
      :style="{ display: showCADetailsModal ? 'block' : 'none' }"
      tabindex="-1"
      @click.self="showCADetailsModal = false"
    >
      <div class="modal-dialog modal-xl">
        <div
          class="modal-content"
          @click.stop
        >
          <div class="modal-header">
            <h5 class="modal-title">
              <i class="bi bi-shield-check me-2" />
              CA Details: {{ viewingCA?.name }}
            </h5>
            <button
              type="button"
              class="btn-close"
              @click="showCADetailsModal = false"
            />
          </div>
          <div
            v-if="viewingCA"
            class="modal-body"
          >
            <div class="row">
              <!-- Basic Information -->
              <div class="col-lg-6 mb-4">
                <div class="card h-100">
                  <div class="card-header">
                    <h6 class="mb-0">
                      <i class="bi bi-info-circle me-2" />
                      Basic Information
                    </h6>
                  </div>
                  <div class="card-body">
                    <div class="row">
                      <div class="col-sm-4">
                        <strong>Name:</strong>
                      </div>
                      <div class="col-sm-8">
                        {{ viewingCA.name }}
                      </div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4">
                        <strong>Serial:</strong>
                      </div>
                      <div class="col-sm-8">
                        <code>{{ viewingCA.serial_number }}</code>
                      </div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4">
                        <strong>Key Size:</strong>
                      </div>
                      <div class="col-sm-8">
                        {{ viewingCA.key_size }}
                      </div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4">
                        <strong>Algorithm:</strong>
                      </div>
                      <div class="col-sm-8">
                        {{ viewingCA.signature_algorithm }}
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
                          :class="getCATypeText(viewingCA) === 'Self-Signed' ? 'bg-success' : 'bg-info'"
                        >
                          {{ getCATypeText(viewingCA) }}
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
                      <i class="bi bi-calendar-check me-2" />
                      Validity
                    </h6>
                  </div>
                  <div class="card-body">
                    <div class="row">
                      <div class="col-sm-4">
                        <strong>Created:</strong>
                      </div>
                      <div class="col-sm-8">
                        {{ formatDate(viewingCA.created_on) }}
                      </div>
                    </div>
                    <hr>
                    <div class="row">
                      <div class="col-sm-4">
                        <strong>Expires:</strong>
                      </div>
                      <div class="col-sm-8">
                        {{ formatDate(viewingCA.valid_until) }}
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
                          :class="getStatusClass(viewingCA)"
                        >
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
                      <i class="bi bi-person me-2" />
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
                      <i class="bi bi-building me-2" />
                      Issuer
                    </h6>
                  </div>
                  <div class="card-body">
                    <pre class="mb-0 text-break small">{{ viewingCA.issuer }}</pre>
                  </div>
                </div>
              </div>

              <!-- Authority Information Access (AIA) URL -->
              <div class="col-lg-6 mb-4">
                <div class="card h-100">
                  <div class="card-header">
                    <h6 class="mb-0">
                      <i class="bi bi-link-45deg me-2" />
                      Authority Information Access URL
                    </h6>
                  </div>
                  <div class="card-body">
                    <div
                      v-if="viewingCA.aia_url"
                      class="mb-2"
                    >
                      <a
                        :href="viewingCA.aia_url"
                        target="_blank"
                        class="text-break small link-primary text-decoration-none"
                      >
                        {{ viewingCA.aia_url }}
                        <i class="bi bi-box-arrow-up-right ms-1 small" />
                      </a>
                    </div>
                    <div
                      v-else
                      class="text-muted small"
                    >
                      <i class="bi bi-dash-circle me-1" />
                      Not configured
                    </div>
                  </div>
                </div>
              </div>

              <!-- Certificate Revocation List (CDP) URL -->
              <div class="col-lg-6 mb-4">
                <div class="card h-100">
                  <div class="card-header">
                    <h6 class="mb-0">
                      <i class="bi bi-arrow-repeat me-2" />
                      CRL Distribution Point URL
                    </h6>
                  </div>
                  <div class="card-body">
                    <div
                      v-if="viewingCA.cdp_url"
                      class="mb-2"
                    >
                      <a
                        :href="viewingCA.cdp_url"
                        target="_blank"
                        class="text-break small link-primary text-decoration-none"
                      >
                        {{ viewingCA.cdp_url }}
                        <i class="bi bi-box-arrow-up-right ms-1 small" />
                      </a>
                    </div>
                    <div
                      v-else
                      class="text-muted small"
                    >
                      <i class="bi bi-dash-circle me-1" />
                      Not configured
                    </div>
                  </div>
                </div>
              </div>

              <!-- Certificate Chain Information -->
              <div class="col-12 mb-4">
                <div class="card">
                  <div class="card-header d-flex justify-content-between align-items-center">
                    <h6 class="mb-0">
                      <i class="bi bi-diagram-3 me-2" />
                      Certificate Chain
                    </h6>
                    <small class="text-muted">{{ viewingCA.chain_length || 0 }} certificate{{ viewingCA.chain_length !== 1 ? 's' : '' }}</small>
                  </div>
                  <div class="card-body">
                    <!-- Certificates List -->
                    <div
                      v-if="viewingCA.chain_certificates?.length > 0"
                      class="row g-3"
                    >
                      <div
                        v-for="(cert, index) in viewingCA.chain_certificates"
                        :key="index"
                        class="col-md-6"
                      >
                        <div class="certificate-card shadow-sm border rounded p-3">
                          <div class="d-flex align-items-center gap-3 mb-2">
                            <div class="certificate-number">
                              {{ index + 1 }}
                            </div>
                            <span
                              class="badge small"
                              :class="getCertificateTypeClass(cert.certificate_type)"
                            >
                              {{ getCertificateTypeLabel(cert.certificate_type) }}
                            </span>
                          </div>
                          <div class="certificate-info">
                            <div class="mb-1">
                              <strong class="text-dark">Subject:</strong>
                              <br>
                              <small class="text-muted">{{ formatCertificateName(cert.subject) }}</small>
                            </div>
                            <div>
                              <strong class="text-dark">Serial:</strong>
                              <code class="ms-2 small">{{ formatSerialNumber(cert.serial_number) }}</code>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                    <!-- No Chain Information -->
                    <div
                      v-else-if="viewingCA.chain_length > 0"
                      class="alert alert-warning mb-0"
                    >
                      <i class="bi bi-exclamation-triangle me-2" />
                      Certificate chain contains {{ viewingCA.chain_length }} certificate{{ viewingCA.chain_length !== 1 ? 's' : '' }}, but detailed information could not be parsed. The full PEM certificate is available for download.
                    </div>
                    <div
                      v-else
                      class="text-center text-muted py-4"
                    >
                      <i class="bi bi-info-circle fs-1 mb-2 opacity-50" />
                      <p class="mb-0">
                        Certificate chain information is not available for this CA.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Certificate PEM -->
            <div class="card">
              <div class="card-header d-flex justify-content-between align-items-center">
                <h6 class="mb-0">
                  <i class="bi bi-file-earmark-text me-2" />
                  Certificate (PEM Format)
                </h6>
                <div class="btn-group btn-group-sm">
                  <button
                    class="btn btn-outline-secondary"
                    @click="copyToClipboard(viewingCA.certificate_pem)"
                  >
                    <i class="bi bi-clipboard me-1" />
                    Copy
                  </button>
                  <button
                    class="btn btn-outline-primary"
                    @click="downloadCACertificate(viewingCA)"
                  >
                    <i class="bi bi-download me-1" />
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
            <button
              type="button"
              class="btn btn-secondary"
              @click="showCADetailsModal = false"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div
      class="modal fade"
      :class="{ show: showDeleteModal }"
      :style="{ display: showDeleteModal ? 'block' : 'none' }"
      tabindex="-1"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title text-danger">
              <i class="bi bi-exclamation-triangle me-2" />
              Delete Certificate Authority
            </h5>
            <button
              type="button"
              class="btn-close"
              @click="showDeleteModal = false"
            />
          </div>
          <div class="modal-body">
            <p>Are you sure you want to delete the Certificate Authority <strong>{{ deletingCA?.name }}</strong>?</p>
            <div class="alert alert-danger">
              <i class="bi bi-exclamation-triangle me-2" />
              <strong>Warning:</strong> This action cannot be undone. All certificates issued by this CA will become invalid.
            </div>
          </div>
          <div class="modal-footer">
            <button
              type="button"
              class="btn btn-secondary"
              @click="showDeleteModal = false"
            >
              Cancel
            </button>
            <button
              type="button"
              class="btn btn-danger"
              :disabled="deletingCAInProgress"
              @click="performDeleteCA"
            >
              <span
                v-if="deletingCAInProgress"
                class="spinner-border spinner-border-sm me-2"
                role="status"
              />
              Delete CA
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue';
import { useAuthStore } from '@/stores/auth';
import { useSettingsStore } from '@/stores/settings';
import { fetchCAs, createSelfSignedCA, importCAFromFile, deleteCA, downloadCAById, downloadCAKeyPairById } from '@/api/certificates';
import { UserRole } from '@/types/User';
import type { CA } from '@/types/CA';

const authStore = useAuthStore();
const settingsStore = useSettingsStore();

const isAdmin = computed(() => authStore.current_user?.role === UserRole.Admin);
const isRootCA = computed(() => settingsStore.settings?.common?.is_root_ca || false);

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
  countryName: 'QA',
  stateOrProvinceName: 'Doha',
  localityName: 'Bin Omran',
  organizationName: 'Your Organization',
  organizationalUnitName: '',
  commonName: 'subca.yourdomain.com',
  emailAddress: 'pki@yourdomain.com',
  validityYears: 10,
  keyType: 'RSA',
  keySize: '2048',
  password: '',
  caName: '',
  hashAlgorithm: 'sha256',
  crlValidityDays: 30,
  pathLength: 1,
  aiaUrl: '',
  cdpUrl: ''
});

const importForm = ref({
  file: null as File | null,
  password: ''
});

const viewingCA = ref<CA | null>(null);
const deletingCA = ref<CA | null>(null);

// Watch for key type changes and reset key size to appropriate default
watch(() => selfSignedForm.value.keyType, (newKeyType: string) => {
  if (newKeyType === 'RSA' && selfSignedForm.value.keySize !== '2048' && selfSignedForm.value.keySize !== '4096') {
    selfSignedForm.value.keySize = '2048';
  } else if (newKeyType === 'ECDSA' && selfSignedForm.value.keySize !== 'P-256' && selfSignedForm.value.keySize !== 'P-521') {
    selfSignedForm.value.keySize = 'P-256';
  }
});

const fileInput = ref<HTMLInputElement | null>(null);

const handleAddCA = () => {
  if (isRootCA.value) {
    // In Root CA Server Mode: can create subordinate CAs
    caCreationType.value = 'self-signed';
    showAddCAModal.value = true;
  } else {
    // In Normal Mode: can only import existing CAs
    caCreationType.value = 'import';
    showAddCAModal.value = true;
  }
};

const loadCAs = async () => {
  try {
    loading.value = true;
    error.value = null;
    cas.value = await fetchCAs();
  } catch (err: unknown) {
    console.error('Failed to load CAs:', err);
    error.value = `Failed to load CAs: ${err instanceof Error ? err.message : String(err)}`;
  } finally {
    loading.value = false;
  }
};

const viewCADetails = (ca: CA) => {
  viewingCA.value = ca;
  showCADetailsModal.value = true;
};

const handleDownloadCAKeyPair = async (ca: CA) => {
  try {
    await downloadCAKeyPairById(ca.id);
  } catch (err: unknown) {
    console.error('Failed to download CA key pair:', err);
    alert('Failed to download CA certificate and private key');
  }
};



const confirmDeleteCA = (ca: CA) => {
  deletingCA.value = ca;
  showDeleteModal.value = true;
};

const createSelfSignedCAWrapper = async () => {
  try {
    creatingCA.value = true;
    const id = await createSelfSignedCA(
      selfSignedForm.value.caName || selfSignedForm.value.commonName || 'My Root CA', // CA display name, fallback to Common Name
      selfSignedForm.value.validityYears,
      selfSignedForm.value.password || undefined,
      selfSignedForm.value.countryName || undefined,
      selfSignedForm.value.stateOrProvinceName || undefined,
      selfSignedForm.value.localityName || undefined,
      selfSignedForm.value.organizationName || undefined,
      selfSignedForm.value.organizationalUnitName || undefined,
      selfSignedForm.value.commonName || undefined, // CN field
      selfSignedForm.value.emailAddress || undefined,
      true, // canCreateSubordinateCA - always true for Root CA mode
      selfSignedForm.value.keyType === 'RSA'
        ? parseInt(selfSignedForm.value.keySize)
        : (selfSignedForm.value.keyType === 'ECDSA'
            ? (selfSignedForm.value.keySize === 'P-256' ? 256 : 521) // P-256 -> 256, P-521 -> 521
            : undefined), // For ECDSA, convert curve names to numeric equivalents
      undefined, // certificatePoliciesOID - not used in first-time setup
      undefined, // certificatePoliciesCPS - not used in first-time setup
      selfSignedForm.value.keyType
    );
    console.log('Created CA with ID:', id);
    await loadCAs(); // Refresh CA list after creation
    showAddCAModal.value = false;
    resetForms();
  } catch (err: unknown) {
    console.error('Failed to create CA:', err);
    alert(`Failed to create CA: ${err instanceof Error ? err.message : String(err)}`);
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
    await loadCAs(); // Refresh CA list after import
    showAddCAModal.value = false;
    resetForms();
  } catch (err: unknown) {
    console.error('Failed to import CA:', err);
    alert(`Failed to import CA: ${err instanceof Error ? err.message : String(err)}`);
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
  } catch (err: unknown) {
    console.error('Failed to delete CA:', err);
    alert(`Failed to delete CA: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    deletingCAInProgress.value = false;
  }
};

const resetForms = () => {
  caCreationType.value = null;
  selfSignedForm.value = {
    countryName: 'QA',
    stateOrProvinceName: 'Doha',
    localityName: 'Bin Omran',
    organizationName: 'Your Organization',
    organizationalUnitName: '',
    commonName: 'rootca.yourdomain.com',
    emailAddress: 'pki@yourdomain.com',
    validityYears: 10,
    keyType: 'RSA',
    keySize: '2048',
    password: '',
    caName: '',
    hashAlgorithm: 'sha256',
    crlValidityDays: 30,
    pathLength: 1,
    aiaUrl: '',
    cdpUrl: ''
  };
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
  try {
    await downloadCAById(ca.id);
  } catch (err: unknown) {
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
    // Calculate remaining days for valid certificates
    const daysRemaining = Math.ceil((validUntil - now) / (1000 * 60 * 60 * 24));
    return `Valid for ${daysRemaining} days`;
  }
};

const getStatusClass = (ca: CA): string => {
  const now = Date.now();
  const validUntil = ca.valid_until;

  if (validUntil < now) {
    return 'bg-danger'; // Expired - red
  } else if (validUntil < now + (30 * 24 * 60 * 60 * 1000)) { // 30 days
    return 'bg-warning text-dark'; // Expiring Soon - yellow
  } else {
    return 'bg-success'; // Valid - green
  }
};

const formatSerialNumber = (serial: string): string => {
  // Format long serial numbers by inserting spaces every few characters for readability
  if (serial.length <= 12) {
    return serial;
  }
  return serial.match(/.{1,4}/g)?.join(' ') || serial;
};

const getCertificateTypeClass = (certificateType: string): string => {
  switch (certificateType) {
    case 'end_entity':
      return 'bg-primary';
    case 'intermediate_ca':
      return 'bg-info';
    case 'root_ca':
      return 'bg-warning text-dark';
    default:
      return 'bg-secondary';
  }
};

const getCertificateTypeLabel = (certificateType: string): string => {
  switch (certificateType) {
    case 'end_entity':
      return 'End Entity';
    case 'intermediate_ca':
      return 'Intermediate CA';
    case 'root_ca':
      return 'Root CA';
    default:
      return 'Unknown';
  }
};

const formatCertificateName = (subject: string): string => {
  // Extract common name (CN) from subject string
  if (!subject) return '';

  // Look for CN= value in the subject
  const cnMatch = subject.match(/CN\s*=\s*([^,\n]+)/i);
  if (cnMatch && cnMatch[1]) {
    return cnMatch[1].trim();
  }

  // If no CN found, return a truncated version of the subject
  const colonIndex = subject.indexOf(':');
  if (colonIndex !== -1 && colonIndex < subject.length - 1) {
    const name = subject.substring(colonIndex + 1).trim();
    return name.length > 50 ? name.substring(0, 50) + '...' : name;
  }

  return subject.length > 50 ? subject.substring(0, 50) + '...' : subject;
};

const getCATypeText = (ca: CA): string => {
  if (ca.is_self_signed) {
    return 'Self-Signed';
  }

  // Check if imported CA has intermediate CA and root CA in chain
  if (ca.chain_certificates) {
    const hasIntermediateCA = ca.chain_certificates.some(cert => cert.certificate_type === 'intermediate_ca');
    const hasRootCA = ca.chain_certificates.some(cert => cert.certificate_type === 'root_ca');

    if (hasIntermediateCA && hasRootCA) {
      return 'Imported SubCA';
    }
  }

  return 'Imported';
};

onMounted(() => {
  loadCAs();
});

// Close modals when clicking outside
// This could be improved with a modal component
</script>

<style scoped>
.ca-tools-container {
  background-color: transparent;
  width: 100%;
}

.ca-tools-container .table-responsive {
  width: 100%;
}

.ca-tools-container .table {
  width: 100%;
}

.certificate-pem {
  background-color: var(--color-hover);
  color: var(--color-text-primary);
  padding: var(--spacing-md);
  border-radius: var(--radius-md);
  font-family: 'SF Mono', SFMono-Regular, ui-monospace, 'DejaVu Sans Mono', Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 400px;
  overflow-y: auto;
  border: 1px solid var(--color-border);
}

@media (max-width: 768px) {
  .ca-tools-container {
    padding: 0;
  }
}

/* Certificate Chain Card Styles */
.certificate-card {
  transition: all var(--transition-normal);
  background: var(--color-card);
  border-left: 4px solid var(--primary);
  border-radius: var(--radius-md);
  margin-bottom: var(--spacing-md);
  padding: var(--spacing-md);
}

.certificate-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

.certificate-card .certificate-number {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--primary);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: var(--font-weight-bold);
  font-size: 14px;
}
</style>
