export enum CAType {
    SelfSigned = 0,
    Imported = 1
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
}

export interface CAAndCertificate extends CA {
    // Additional fields that may come from the CA + Certificate combination
}
