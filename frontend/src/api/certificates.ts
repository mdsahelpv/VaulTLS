import ApiClient from './ApiClient';
import type {Certificate, CertificateDetails} from '@/types/Certificate';
import type {CertificateRequirements} from "@/types/CertificateRequirements.ts";
import type {CAAndCertificate} from '@/types/CA';

export const fetchCertificates = async (): Promise<Certificate[]> => {
    return await ApiClient.get<Certificate[]>('/certificates');
};

export const fetchCertificatePassword = async (id: number): Promise<string> => {
    return await ApiClient.get<string>(`/certificates/${id}/password`);
};

export const downloadCertificate = async (id: number, certName: string, format: string = 'pkcs12'): Promise<void> => {
    try {
        const certificate = await ApiClient.download(`/certificates/${id}/download?format=${format}`);
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
    const cert = await ApiClient.post<Certificate>('/certificates', certReq);
    return cert.id;
};

export const deleteCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/${id}`);
};

export const revokeCertificate = async (id: number, reason: number, notifyUser: boolean): Promise<void> => {
    await ApiClient.post<void>(`/certificates/${id}/revoke`, {
        revocation_reason: reason,
        notify_user: notifyUser
    });
};

export const getCertificateDetails = async (id: number): Promise<CertificateDetails> => {
    return await ApiClient.get<CertificateDetails>(`/certificates/${id}/details`);
};

export const downloadCA = async (): Promise<void> => {
    return await ApiClient.download('/certificates/ca/download');
};

export const fetchCAs = async (): Promise<CAAndCertificate[]> => {
    return await ApiClient.get<CAAndCertificate[]>('/certificates/ca');
};

export const createSelfSignedCA = async (name: string, validityInYears: number, caPassword?: string): Promise<number> => {
    return await ApiClient.post<number>('/certificates/ca/new', {
        name,
        validity_in_years: validityInYears,
        password: caPassword
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
