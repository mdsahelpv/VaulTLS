import { defineStore } from 'pinia';
import type { Certificate } from '@/types/Certificate';
import {
    fetchCertificates,
    fetchCertificatePassword,
    downloadCertificate,
    createCertificate,
    deleteCertificate,
    revokeCertificate as revokeCertificateApi,
    previewCsr,
    signCsrCertificate,
    type CsrPreviewResponse,
} from '@/api/certificates';
import type { CertificateRequirements } from "@/types/CertificateRequirements.ts";

export const useCertificateStore = defineStore('certificate', {
    state: () => ({
        certificates: new Map<number, Certificate>(),
        // Specific loading states for different operations
        loadingCertificates: false,
        creatingCertificate: false,
        deletingCertificate: false,
        revokingCertificate: false,
        downloadingCertificate: false,
        signingCsr: false,
        previewingCsr: false,
        fetchingPassword: false,
        error: null as string | null,
    }),

    getters: {
        // Global loading state - true if any operation is in progress
        loading: (state): boolean => {
            return state.loadingCertificates ||
                   state.creatingCertificate ||
                   state.deletingCertificate ||
                   state.revokingCertificate ||
                   state.downloadingCertificate ||
                   state.signingCsr ||
                   state.previewingCsr ||
                   state.fetchingPassword;
        },

        // Get certificates as array for easier template usage
        certificatesList: (state): Certificate[] => Array.from(state.certificates.values()),

        // Get certificate by ID
        getCertificateById: (state) => (id: number): Certificate | undefined => {
            return state.certificates.get(id);
        },

        // Get active (non-expired, non-revoked) certificates
        activeCertificates: (state): Certificate[] => {
            const now = Date.now() / 1000; // Convert to seconds
            return Array.from(state.certificates.values()).filter(cert =>
                !cert.is_revoked && parseInt(cert.valid_until) > now
            );
        },

        // Get expired certificates
        expiredCertificates: (state): Certificate[] => {
            const now = Date.now() / 1000; // Convert to seconds
            return Array.from(state.certificates.values()).filter(cert =>
                parseInt(cert.valid_until) <= now
            );
        },

        // Get revoked certificates
        revokedCertificates: (state): Certificate[] => {
            return Array.from(state.certificates.values()).filter(cert => cert.is_revoked);
        },
    },

    actions: {
        // ============ DATA FETCHING ACTIONS ============

        /**
         * Fetch all certificates from the API and update local state
         */
        async fetchCertificates(): Promise<void> {
            // Prevent duplicate requests
            if (this.loadingCertificates) {
                return;
            }

            this.loadingCertificates = true;
            this.error = null;

            try {
                const certificates = await fetchCertificates();
                this.updateCertificates(certificates);
            } catch (err: unknown) {
                this.error = 'Failed to fetch certificates';
                console.error('Error fetching certificates:', err);
                throw err;
            } finally {
                this.loadingCertificates = false;
            }
        },

        /**
         * Fetch password for a specific certificate
         */
        async fetchCertificatePassword(id: number): Promise<string> {
            // Prevent duplicate requests for the same certificate
            if (this.fetchingPassword) {
                throw new Error('Password fetch already in progress');
            }

            this.fetchingPassword = true;
            this.error = null;

            try {
                const password = await fetchCertificatePassword(id);
                this.updateCertificatePassword(id, password);
                return password;
            } catch (err: unknown) {
                this.error = 'Failed to fetch certificate password';
                console.error('Error fetching certificate password:', err);
                throw err;
            } finally {
                this.fetchingPassword = false;
            }
        },

        // ============ CERTIFICATE MANAGEMENT ACTIONS ============

        /**
         * Create a new certificate
         */
        async createCertificate(certReq: CertificateRequirements): Promise<void> {
            // Prevent duplicate creation requests
            if (this.creatingCertificate) {
                throw new Error('Certificate creation already in progress');
            }

            this.creatingCertificate = true;
            this.error = null;
            const previousCertificates = new Map(this.certificates); // Store previous state for rollback

            try {
                await createCertificate(certReq);
                await this.fetchCertificates(); // Refresh the list
            } catch (err: unknown) {
                // Rollback: restore previous state
                this.certificates = previousCertificates;
                this.error = 'Failed to create certificate';
                console.error('Error creating certificate:', err);
                throw err;
            } finally {
                this.creatingCertificate = false;
            }
        },

        /**
         * Delete a certificate by ID
         */
        async deleteCertificate(id: number): Promise<void> {
            // Prevent duplicate deletion requests
            if (this.deletingCertificate) {
                throw new Error('Certificate deletion already in progress');
            }

            this.deletingCertificate = true;
            this.error = null;
            const previousCertificates = new Map(this.certificates); // Store previous state for rollback

            try {
                await deleteCertificate(id);
                // Refresh to get updated state from server (no optimistic updates)
                await this.fetchCertificates();
            } catch (err: unknown) {
                // Rollback: restore previous state
                this.certificates = previousCertificates;
                this.error = 'Failed to delete certificate';
                console.error('Error deleting certificate:', err);
                throw err;
            } finally {
                this.deletingCertificate = false;
            }
        },

        /**
         * Revoke a certificate
         */
        async revokeCertificate(id: number, reason: number, notifyUser: boolean, customReason?: string): Promise<void> {
            // Prevent duplicate revocation requests
            if (this.revokingCertificate) {
                throw new Error('Certificate revocation already in progress');
            }

            this.revokingCertificate = true;
            this.error = null;
            const previousCertificates = new Map(this.certificates); // Store previous state for rollback

            try {
                await revokeCertificateApi(id, reason, notifyUser, customReason);
                await this.fetchCertificates(); // Refresh to get updated revocation status
            } catch (err: unknown) {
                // Rollback: restore previous state
                this.certificates = previousCertificates;
                this.error = 'Failed to revoke certificate';
                console.error('Error revoking certificate:', err);
                throw err;
            } finally {
                this.revokingCertificate = false;
            }
        },

        // ============ DOWNLOAD ACTIONS ============

        /**
         * Download a certificate in the specified format
         */
        async downloadCertificate(id: number, format: string = 'pkcs12'): Promise<void> {
            // Prevent duplicate download requests
            if (this.downloadingCertificate) {
                throw new Error('Certificate download already in progress');
            }

            this.downloadingCertificate = true;
            this.error = null;

            try {
                const certificate = this.certificates.get(id);
                if (!certificate) {
                    throw new Error(`Certificate with ID ${id} not found`);
                }
                await downloadCertificate(id, certificate.name, format);
            } catch (err: unknown) {
                this.error = 'Failed to download certificate';
                console.error('Error downloading certificate:', err);
                throw err;
            } finally {
                this.downloadingCertificate = false;
            }
        },

        // ============ CSR OPERATIONS ============

        /**
         * Sign a Certificate Signing Request
         */
        async signCsrCertificate(formData: FormData): Promise<Certificate> {
            // Prevent duplicate CSR signing requests
            if (this.signingCsr) {
                throw new Error('CSR signing already in progress');
            }

            this.signingCsr = true;
            this.error = null;

            try {
                const certificate = await signCsrCertificate(formData);
                await this.fetchCertificates(); // Refresh the list
                return certificate;
            } catch (err: unknown) {
                this.error = 'Failed to sign CSR';
                console.error('Error signing CSR:', err);
                throw err;
            } finally {
                this.signingCsr = false;
            }
        },

        /**
         * Preview a CSR file to show its contents
         */
        async previewCsr(formData: FormData): Promise<CsrPreviewResponse> {
            // Prevent duplicate CSR preview requests
            if (this.previewingCsr) {
                throw new Error('CSR preview already in progress');
            }

            this.previewingCsr = true;
            this.error = null;

            try {
                return await previewCsr(formData);
            } catch (err: unknown) {
                this.error = 'Failed to preview CSR';
                console.error('Error previewing CSR:', err);
                throw err;
            } finally {
                this.previewingCsr = false;
            }
        },

        // ============ STATE MANAGEMENT HELPERS ============

        /**
         * Update certificates in the store
         */
        updateCertificates(certificates: Certificate[]): void {
            // Clear existing certificates
            this.certificates.clear();

            // Add new certificates
            if (certificates) {
                for (const cert of certificates) {
                    this.certificates.set(cert.id, cert);
                }
            }
        },

        /**
         * Update password for a specific certificate
         */
        updateCertificatePassword(id: number, password: string): void {
            const certificate = this.certificates.get(id);
            if (certificate) {
                certificate.pkcs12_password = password;
            }
        },

        // ============ UTILITY METHODS ============

        /**
         * Clear any current error
         */
        clearError(): void {
            this.error = null;
        },

        /**
         * Check if a certificate exists in the store
         */
        hasCertificate(id: number): boolean {
            return this.certificates.has(id);
        },
    },
});
