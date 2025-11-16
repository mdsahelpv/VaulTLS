export interface SetupReq {
    name: string,
    email: string,
    ca_name: string,
    ca_validity_in_years: number,
    password: string | null;
    ca_type: 'self_signed' | 'upload';
    key_type?: string;
    key_size?: string;
    hash_algorithm?: string;
    pfx_file?: File;
    pfx_password?: string;
    countryName?: string;
    stateOrProvinceName?: string;
    localityName?: string;
    organizationName?: string;
    organizationalUnitName?: string;
    commonName?: string;
    emailAddress?: string;
    is_root_ca?: boolean;
}

export interface IsSetupResponse {
    setup: boolean,
    password: boolean,
    oidc: string;
}

export interface ChangePasswordReq {
    old_password: string | null,
    new_password: string;
}
