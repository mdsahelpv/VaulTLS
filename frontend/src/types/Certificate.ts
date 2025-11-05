export enum CertificateType {
    Client = 0,
    Server = 1,
    CA = 2
}

export enum CertificateRenewMethod {
    None = 0,
    Notify = 1,
    Renew = 2,
    RenewAndNotify = 3
}

export interface Certificate {
    id: number;                           // Unique identifier for the certificate
    name: string;                         // Certificate name
    created_on: string;                   // Date when the certificate was created (UNIX timestamp in ms)
    pkcs12_password: string;              // PKCS12 decryption password
    valid_until: string;                  // Expiration date of the certificate (UNIX timestamp in ms)
    certificate_type: CertificateType;    // Type of the certificate
    user_id: number;                      // User ID who owns the certificate
    renew_method: CertificateRenewMethod; // Method on what to do when the certificate is about to expire
    is_revoked?: boolean;                 // Whether the certificate has been revoked
    revoked_on?: number;                  // Date when the certificate was revoked (UNIX timestamp in ms)
    revoked_reason?: string;              // Reason for revocation
    revoked_by?: number;                  // User ID who revoked the certificate
}

export interface CASummary {
    id: number;
    name: string;
    is_self_signed: boolean;
    valid_until: number;
}

export interface CADetails {
    id: number;
    name: string;
    subject: string;
    issuer: string;
    created_on: number;
    valid_until: number;
    serial_number: string;
    key_size: string;
    signature_algorithm: string;
    is_self_signed: boolean;
    certificate_pem: string;
}

export interface CertificateDetails {
    id: number;
    name: string;
    subject: string;
    issuer: string;
    created_on: number;
    valid_until: number;
    serial_number: string;
    key_size: string;
    signature_algorithm: string;
    certificate_type: CertificateType;
    user_id: number;
    renew_method: CertificateRenewMethod;
    certificate_pem: string;
    is_revoked?: boolean;
    revoked_on?: number;
    revoked_reason?: number;
    revoked_by?: number;
}
