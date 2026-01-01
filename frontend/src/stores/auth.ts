import { defineStore } from 'pinia';
import {change_password, current_user, login, logout} from "@/api/auth.ts";
import type {ChangePasswordReq} from "@/types/Login.ts";
import type {User} from "@/types/User.ts";
import {UserRole} from "@/types/User.ts";

export const useAuthStore = defineStore('auth', {
    state: () => ({
        isAuthenticated: false as boolean,
        current_user: null as User | null,
        error: null as string | null,
    }),
    getters: {
        isAdmin(state): boolean {
            return state.current_user?.role === UserRole.Admin;
        }
    },
    actions: {
        async init() {
            const wasAuthenticated = localStorage.getItem('is_authenticated') === 'true';
            if (wasAuthenticated) {
                try {
                    await this.fetchCurrentUser();
                } catch {
                    // Clear stale authentication state without API calls
                    this.setAuthentication(false);
                }
            }
        },

        // Trigger the login of a user by email and password
        async login(email: string, password: string) {
            this.error = null;

            try {
                await login({ email, password });

                this.current_user = await current_user();
                this.setAuthentication(true);
                return true;
            } catch (err) {
                this.error = 'Failed to login.';
                console.error(err);
                return false;
            }
        },

        // Change the password of the current user
        async changePassword(oldPassword: string, newPassword: string) {
            try {
                this.error = null;
                const changePasswordReq: ChangePasswordReq = {
                    old_password: oldPassword,
                    new_password: newPassword,
                };
                await change_password(changePasswordReq);
                return true;
            } catch (err) {
                this.error = 'Failed to change password.';
                console.error(err);
                return false;
            }
        },

        // Fetch current user and update the state
        async fetchCurrentUser() {
            try {
                this.error = null;
                this.current_user = (await current_user());
                this.setAuthentication(true);
            } catch (err) {
                this.error = 'Failed to fetch current user.';
                console.error(err);
                throw err; // Let caller handle the error
            }
        },

        // Trigger the login of a user by OIDC
        async finishOIDC() {
            await this.fetchCurrentUser()
            this.setAuthentication(true);
        },

        // Set the authentication state and store it in local storage
        setAuthentication(isAuthenticated: boolean) {
            if (isAuthenticated) {
                this.isAuthenticated = true;
                localStorage.setItem('is_authenticated', String(true));
            } else {
                this.isAuthenticated = false;
                localStorage.removeItem('is_authenticated');
            }
        },

        // Log out the user and clear the authentication state
        async logout() {
            // Clear local state first
            this.setAuthentication(false);
            try {
                await logout()
            } catch (err) {
                // Ignore logout failures - we're already logged out locally
            }
        },
    },
});
