import ApiClient from './ApiClient';
import type {Certificate, CertificateDetails, CrlMetadata, CrlFileInfo} from '@/types/Certificate';
import type {CertificateRequirements} from "@/types/CertificateRequirements.ts";
import type {CAAndCertificate} from '@/types/CA';

export const fetchCertificates = async (): Promise<Certificate[]> => {
    return await ApiClient.get<Certificate[]>('/certificates/cert');
};

export const fetchCertificatePassword = async (id: number): Promise<string> => {
    return await ApiClient.get<string>(`/certificates/cert/${id}/password`);
};

export const downloadCertificate = async (id: number, certName: string, format: string = 'pkcs12'): Promise<void> => {
    try {
        await ApiClient.download(`/certificates/cert/${id}/download?format=${format}`);
        // The ApiClient.download method creates a blob and triggers download
        // File naming is handled internally
    } catch (error) {
        console.error('Failed to download certificate:', error);
        throw error;
    }
};

export const createCertificate = async (certReq: CertificateRequirements): Promise<number> => {
    const cert = await ApiClient.post<Certificate>('/certificates/cert', certReq);
    return cert.id;
};

export const deleteCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/cert/${id}`);
};

interface CreateSelfSignedCAPayload {
    name: string;
    validity_in_years: number;
    key_type?: string;
    key_size?: number;
    password?: string;
    country_name?: string;
    state_or_province_name?: string;
    locality_name?: string;
    organization_name?: string;
    organizational_unit_name?: string;
    common_name?: string;
    email_address?: string;
    can_create_subordinate_ca?: boolean;
    certificate_policies_oid?: string;
    certificate_policies_cps?: string;
}

export interface RevocationHistoryEntry {
    id: number;
    certificate_id: number;
    certificate_name: string;
    revocation_date: number; // timestamp in milliseconds
    revocation_reason: number;
    revocation_reason_text: string; // human-readable reason text
    custom_reason?: string;
    revoked_by_user_id?: number;
    reason?: number; // alias for revocation_reason (backward compatibility)
    revoked_on?: number; // alias for revocation_date (backward compatibility)
    revoked_by?: number; // alias for revoked_by_user_id (backward compatibility)
}

interface RevocationStatus {
    certificate_id: number;
    is_revoked: boolean;
    reason?: number;
    custom_reason?: string;
    revoked_on?: string;
    revoked_by?: number;
}

interface RevokeCertificatePayload {
    reason: number;
    notify_user: boolean;
    custom_reason?: string;
}

export const revokeCertificate = async (id: number, reason: number, notifyUser: boolean, customReason?: string): Promise<void> => {
    const payload: RevokeCertificatePayload = {
        reason: reason,
        notify_user: notifyUser
    };

    // Only include custom_reason when reason=2 (Specify)
    if (reason === 2) {
        payload.custom_reason = customReason || '';
    }

    await ApiClient.post<void>(`/certificates/cert/${id}/revoke`, payload);
};

export const getCertificateDetails = async (id: number): Promise<CertificateDetails> => {
    return await ApiClient.get<CertificateDetails>(`/certificates/cert/${id}/details`);
};

export const downloadCA = async (): Promise<void> => {
    return await ApiClient.download('/certificates/ca/download');
};

export const downloadCAKeyPair = async (): Promise<void> => {
    return await ApiClient.download('/certificates/ca/download_key');
};

export const downloadCAById = async (id: number): Promise<void> => {
    return await ApiClient.download(`/certificates/ca/${id}/download`);
};

export const downloadCAKeyPairById = async (id: number): Promise<void> => {
    return await ApiClient.download(`/certificates/ca/${id}/download_key`);
};

export const fetchCAs = async (): Promise<CAAndCertificate[]> => {
    return await ApiClient.get<CAAndCertificate[]>('/certificates/ca/list');
};

export const createSelfSignedCA = async (
    name: string,
    validityInYears: number,
    caPassword?: string,
    countryName?: string,
    stateOrProvinceName?: string,
    localityName?: string,
    organizationName?: string,
    organizationalUnitName?: string,
    commonName?: string,
    emailAddress?: string,
    canCreateSubordinateCA?: boolean,
    keySize?: number,
    certificatePoliciesOID?: string,
    certificatePoliciesCPS?: string,
    keyType?: string
): Promise<number> => {
    const payload: CreateSelfSignedCAPayload = {
        name,
        validity_in_years: validityInYears,
        key_type: keyType,
        key_size: keySize,
        password: caPassword,
        country_name: countryName,
        state_or_province_name: stateOrProvinceName,
        locality_name: localityName,
        organization_name: organizationName,
        organizational_unit_name: organizationalUnitName,
        common_name: commonName,
        email_address: emailAddress,
        can_create_subordinate_ca: canCreateSubordinateCA,
        certificate_policies_oid: certificatePoliciesOID,
        certificate_policies_cps: certificatePoliciesCPS
    };

    return await ApiClient.post<number>('/certificates/ca/new', payload);
};

export const importCAFromFile = async (formData: FormData): Promise<number> => {
    return await ApiClient.post<number>('/certificates/ca/import', formData, {
        headers: {
            'Content-Type': 'multipart/form-data',
        },
    });
};

export const deleteCA = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/ca/${id}`);
};

export const getRevocationHistory = async (): Promise<RevocationHistoryEntry[]> => {
    return await ApiClient.get<RevocationHistoryEntry[]>('/certificates/revocation-history');
};

export const clearRevocationHistory = async (): Promise<void> => {
    await ApiClient.delete<void>('/certificates/revocation-history');
};

export const unrevokeCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/cert/${id}/revoke`);
};

export const getRevocationStatus = async (id: number): Promise<RevocationStatus> => {
    return await ApiClient.get<RevocationStatus>(`/certificates/cert/${id}/revocation-status`);
};

export const downloadCRL = async (): Promise<void> => {
    return await ApiClient.download('/certificates/crl');
};

export const getCrlMetadata = async (): Promise<CrlMetadata> => {
    return await ApiClient.get<CrlMetadata>('/certificates/crl/metadata');
};

export const listCrlFiles = async (): Promise<CrlFileInfo[]> => {
    return await ApiClient.get<CrlFileInfo[]>('/certificates/crl/files');
};

export const downloadCrlBackup = async (filename: string): Promise<void> => {
    return await ApiClient.download(`/certificates/crl/backup/${filename}`);
};

export const deleteCrlBackup = async (filename: string): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/crl/backup/${filename}`);
};

export const generateCRL = async (): Promise<{ success: boolean; message: string }> => {
    return await ApiClient.post<{ success: boolean; message: string }>('/certificates/crl/generate');
};

export interface CrlDetails {
    ca_id: number;
    ca_name: string;
    issuer: string;
    this_update: number;
    next_update: number;
    version: number;
    signature_algorithm: string;
    revoked_certificates_count: number;
    file_size: number;
}

export const getCrlDetails = async (): Promise<CrlDetails> => {
    return await ApiClient.get<CrlDetails>('/certificates/crl/details');
};

export interface CsrSignRequest {
    ca_id?: string;
    certificate_type: string;
    cert_name: string;
    user_id: string;
    validity_in_days?: string;
}

export const signCsrCertificate = async (formData: FormData): Promise<Certificate> => {
    return await ApiClient.post<Certificate>('/certificates/cert/sign-csr', formData, {
        headers: {
            'Content-Type': 'multipart/form-data',
        },
    });
};

export interface CsrPreviewResponse {
    common_name?: string;
    organization_name?: string;
    organizational_unit_name?: string;
    locality_name?: string;
    state_or_province_name?: string;
    country_name?: string;
    email_address?: string;
    algorithm: string;
    key_size: string;
    signature_valid: boolean;
    subject_alt_names: string[];
}

export const previewCsr = async (formData: FormData): Promise<CsrPreviewResponse> => {
    return await ApiClient.post<CsrPreviewResponse>('/certificates/csr/preview', formData, {
        headers: {
            'Content-Type': 'multipart/form-data',
        },
    });
};
