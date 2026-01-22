export enum CAType {
    SelfSigned = 0,
    Imported = 1
}

export interface CertificateChainInfo {
    subject: string;              // Certificate subject
    issuer: string;               // Certificate issuer
    serial_number: string;        // Certificate serial number
    certificate_type: string;     // Type of certificate ("end_entity", "intermediate_ca", "root_ca")
    is_end_entity: boolean;       // Whether this is the end-entity certificate
}

export interface CA {
    id: number;                    // Unique identifier for the CA
    name: string;                  // CA certificate name
    subject: string;               // Certificate subject
    issuer: string;                // Certificate issuer
    created_on: number;            // Date when the CA was created (UNIX timestamp in ms)
    valid_until: number;           // Expiration date of the CA certificate (UNIX timestamp in ms)
    serial_number: string;         // Certificate serial number
    key_size: string;              // Key size (e.g., "RSA 2048")
    signature_algorithm: string;   // Signature algorithm (e.g., "RSA-SHA256")
    is_self_signed: boolean;       // Whether this is a self-signed CA
    certificate_pem: string;       // PEM-encoded certificate data
    chain_length: number;          // Total number of certificates in the chain
    chain_certificates: CertificateChainInfo[]; // Details of each certificate in the chain
    can_create_subordinate_ca?: boolean; // Whether this CA can create subordinate CAs
    aia_url?: string;              // Authority Information Access URL
    cdp_url?: string;              // Certificate Revocation List Distribution Point URL
}

export type CAAndCertificate = CA;
