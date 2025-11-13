import type {SetupReq, IsSetupResponse, ChangePasswordReq} from "@/types/Login.ts";
import ApiClient from "@/api/ApiClient.ts";
import type {User} from "@/types/User.ts";

export const is_setup = async (): Promise<IsSetupResponse> => {
    return await ApiClient.get<IsSetupResponse>('/server/setup');
};


export const setup = async (setupReq: SetupReq): Promise<void> => {
    // If uploading a PFX file, use FormData
    if (setupReq.ca_type === 'upload' && setupReq.pfx_file) {
        const formData = new FormData();
        formData.append('name', setupReq.name);
        formData.append('email', setupReq.email);
        formData.append('ca_name', setupReq.ca_name);
        formData.append('ca_validity_in_years', setupReq.ca_validity_in_years.toString());
        formData.append('ca_type', setupReq.ca_type);
        formData.append('pfx_file', setupReq.pfx_file);
        if (setupReq.pfx_password) {
            formData.append('pfx_password', setupReq.pfx_password);
        }
        if (setupReq.password && setupReq.password.trim() !== '') {
            formData.append('password', setupReq.password);
        }

        // Use a custom request with FormData
        const response = await fetch('/api/server/setup/form', {
            method: 'POST',
            body: formData,
            credentials: 'include',
        });

        if (!response.ok) {
            let errorMessage = 'Setup failed';
            try {
                const errorData = await response.json();
                if (errorData.error) {
                    errorMessage = errorData.error;
                } else if (errorData.message) {
                    errorMessage = errorData.message;
                }
            } catch {
                // If JSON parsing fails, try to get text
                try {
                    const errorText = await response.text();
                    if (errorText) {
                        errorMessage = errorText;
                    }
                } catch {
                    // Use default error message
                }
            }
            throw new Error(errorMessage);
        }

        return;
    } else {
        // Use regular JSON for self-signed CA
        const jsonData = {
            name: setupReq.name,
            email: setupReq.email,
            ca_name: setupReq.ca_name,
            ca_validity_in_years: setupReq.ca_validity_in_years,
            ca_type: setupReq.ca_type,
            password: setupReq.password,
            key_type: setupReq.key_type,
            key_size: setupReq.key_size,
            hash_algorithm: setupReq.hash_algorithm,
            countryName: setupReq.countryName,
            stateOrProvinceName: setupReq.stateOrProvinceName,
            localityName: setupReq.localityName,
            organizationName: setupReq.organizationName,
            organizationalUnitName: setupReq.organizationalUnitName,
            commonName: setupReq.commonName,
            emailAddress: setupReq.emailAddress,
        };
        return await ApiClient.post<void>('/server/setup', jsonData);
    }
};

export const login = async (loginReq: { email: string | undefined, password: string | undefined }): Promise<void> => {
    return await ApiClient.post<void>('/auth/login', loginReq);
};

export const change_password = async (changePasswordReq: ChangePasswordReq): Promise<void> => {
    return await ApiClient.post<void>('/auth/change_password', changePasswordReq);
};

export const logout = async (): Promise<void> => {
    return await ApiClient.post<void>('/auth/logout');
};

export const current_user = async (): Promise<User> => {
    return await ApiClient.get<User>('/auth/me');
}
