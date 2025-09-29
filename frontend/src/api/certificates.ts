import ApiClient from './ApiClient';
import type {Certificate} from '@/types/Certificate';
import type {CertificateRequirements} from "@/types/CertificateRequirements.ts";
import type {CAAndCertificate} from '@/types/CA';

export const fetchCertificates = async (): Promise<Certificate[]> => {
    return await ApiClient.get<Certificate[]>('/certificates');
};

export const fetchCertificatePassword = async (id: number): Promise<string> => {
    return await ApiClient.get<string>(`/certificates/${id}/password`);
};

export const downloadCertificate = async (id: number): Promise<void> => {
    return await ApiClient.download(`/certificates/${id}/download`);
};

export const createCertificate = async (certReq: CertificateRequirements): Promise<number> => {
    const cert = await ApiClient.post<Certificate>('/certificates', certReq);
    return cert.id;
};

export const deleteCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/${id}`);
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
