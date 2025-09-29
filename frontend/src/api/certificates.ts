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

export const downloadCertificate = async (id: number, certName: string): Promise<void> => {
    try {
        const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/api/certificates/${id}/download`, {
            method: 'GET',
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`Download failed: ${response.status}`);
        }

        const blob = await response.blob();
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = blobUrl;
        link.download = `${certName.replace(/[^a-zA-Z0-9]/g, '_')}.crt`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(blobUrl);
    } catch (error) {
        console.error('Failed to download certificate:', error);
        throw error;
    }
};

export const createCertificate = async (certReq: CertificateRequirements): Promise<number> => {
    const cert = await ApiClient.post<Certificate>('/certificates', certReq);
    return cert.id;
};

export const deleteCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/${id}`);
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
