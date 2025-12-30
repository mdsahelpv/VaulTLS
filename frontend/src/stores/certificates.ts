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
        loading: false,
        error: null as string | null,
    }),

    getters: {
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
            this.loading = true;
            this.error = null;
            try {
                const certificates = await fetchCertificates();
                this.updateCertificates(certificates);
            } catch (err: unknown) {
                this.error = 'Failed to fetch certificates';
                console.error('Error fetching certificates:', err);
                throw err;
            } finally {
                this.loading = false;
            }
        },

        /**
         * Fetch password for a specific certificate
         */
        async fetchCertificatePassword(id: number): Promise<string> {
            try {
                const password = await fetchCertificatePassword(id);
                this.updateCertificatePassword(id, password);
                return password;
            } catch (err: unknown) {
                this.error = 'Failed to fetch certificate password';
                console.error('Error fetching certificate password:', err);
                throw err;
            }
        },

        // ============ CERTIFICATE MANAGEMENT ACTIONS ============

        /**
         * Create a new certificate
         */
        async createCertificate(certReq: CertificateRequirements): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await createCertificate(certReq);
                await this.fetchCertificates(); // Refresh the list
            } catch (err: unknown) {
                this.error = 'Failed to create certificate';
                console.error('Error creating certificate:', err);
                throw err;
            } finally {
                this.loading = false;
            }
        },

        /**
         * Delete a certificate by ID
         */
        async deleteCertificate(id: number): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await deleteCertificate(id);
                this.certificates.delete(id); // Optimistically remove from local state
                await this.fetchCertificates(); // Refresh to ensure consistency
            } catch (err: unknown) {
                this.error = 'Failed to delete certificate';
                console.error('Error deleting certificate:', err);
                throw err;
            } finally {
                this.loading = false;
            }
        },

        /**
         * Revoke a certificate
         */
        async revokeCertificate(id: number, reason: number, notifyUser: boolean, customReason?: string): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await revokeCertificateApi(id, reason, notifyUser, customReason);
                await this.fetchCertificates(); // Refresh to get updated revocation status
            } catch (err: unknown) {
                this.error = 'Failed to revoke certificate';
                console.error('Error revoking certificate:', err);
                throw err;
            } finally {
                this.loading = false;
            }
        },

        // ============ DOWNLOAD ACTIONS ============

        /**
         * Download a certificate in the specified format
         */
        async downloadCertificate(id: number, format: string = 'pkcs12'): Promise<void> {
            try {
                this.error = null;
                const certificate = this.certificates.get(id);
                if (!certificate) {
                    throw new Error(`Certificate with ID ${id} not found`);
                }
                await downloadCertificate(id, certificate.name, format);
            } catch (err: unknown) {
                this.error = 'Failed to download certificate';
                console.error('Error downloading certificate:', err);
                throw err;
            }
        },

        // ============ CSR OPERATIONS ============

        /**
         * Sign a Certificate Signing Request
         */
        async signCsrCertificate(formData: FormData): Promise<Certificate> {
            this.loading = true;
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
                this.loading = false;
            }
        },

        /**
         * Preview a CSR file to show its contents
         */
        async previewCsr(formData: FormData): Promise<CsrPreviewResponse> {
            try {
                this.error = null;
                return await previewCsr(formData);
            } catch (err: unknown) {
                this.error = 'Failed to preview CSR';
                console.error('Error previewing CSR:', err);
                throw err;
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
