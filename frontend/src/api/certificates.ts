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
        const certificate = await ApiClient.download(`/certificates/cert/${id}/download?format=${format}`);
        // Override the filename to use the certificate name and correct extension
        const extension = getExtension(format);
        const filename = `${certName.replace(/[^a-zA-Z0-9]/g, '_')}.${extension}`;

        // The ApiClient.download method creates a blob and triggers download
        // We need to override the filename logic here if needed
        return certificate;
    } catch (error) {
        console.error('Failed to download certificate:', error);
        throw error;
    }
};

const getExtension = (format: string): string => {
    switch (format) {
        case 'pkcs12': return 'p12';
        case 'pem': return 'pem';
        case 'der': return 'der';
        default: return 'crt';
    }
};

export const createCertificate = async (certReq: CertificateRequirements): Promise<number> => {
    const cert = await ApiClient.post<Certificate>('/certificates/cert', certReq);
    return cert.id;
};

export const deleteCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/cert/${id}`);
};

export const revokeCertificate = async (id: number, reason: number, notifyUser: boolean): Promise<void> => {
    await ApiClient.post<void>(`/certificates/cert/${id}/revoke`, {
        reason: reason,
        notify_user: notifyUser
    });
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
    return await ApiClient.post<number>('/certificates/ca/new', {
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
    });
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

export const getRevocationHistory = async (): Promise<any[]> => {
    return await ApiClient.get<any[]>('/certificates/revocation-history');
};

export const clearRevocationHistory = async (): Promise<void> => {
    await ApiClient.delete<void>('/certificates/revocation-history');
};

export const unrevokeCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/cert/${id}/revoke`);
};

export const getRevocationStatus = async (id: number): Promise<any> => {
    return await ApiClient.get<any>(`/certificates/cert/${id}/revocation-status`);
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
