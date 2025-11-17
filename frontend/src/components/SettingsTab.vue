<template>
  <div class="settings-tab">
    <h1>Settings</h1>
    <hr />
    <!-- Application Section -->
    <div v-if="authStore.isAdmin && settings" class="mb-3">
      <!-- Common Section -->
      <h3>Common</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3 form-check form-switch">
            <input
                type="checkbox"
                class="form-check-input"
                id="common-password-enabled"
                v-model="settings.common.password_enabled"
                role="switch"
            />
            <label class="form-check-label" for="common-password-enabled">
              Password Login enabled
            </label>
          </div>
          <div class="mb-3">
            <label for="common-vaultls-url" class="form-label">VaulTLS URL</label>
            <input
                id="common-vaultls-url"
                v-model="settings.common.vaultls_url"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="common-password-rule" class="form-label">PKCS12 Password Rules</label>
            <select
                id="common-password-rule"
                v-model="settings.common.password_rule"
                class="form-select"
            >
              <option :value="PasswordRule.Optional">Optional</option>
              <option :value="PasswordRule.Required">Required</option>
              <option :value="PasswordRule.System">System Generated</option>
            </select>
          </div>

          <!-- Root CA Mode Warning Section -->
          <div class="mb-3 form-check form-switch">
            <input
                type="checkbox"
                class="form-check-input"
                id="common-is-root-ca"
                v-model="settings.common.is_root_ca"
                role="switch"
                @change="toggleRootCAMode"
            />
            <label class="form-check-label" for="common-is-root-ca">
              <strong>Root CA Server Mode</strong>
              <small class="text-muted d-block mt-1">
                Restricts certificate issuance to subordinate CA certificates only.
                Client and server certificates must be issued by subordinate CAs.
              </small>
            </label>
          </div>

          <!-- Warning Alert for Root CA Mode -->
          <div v-if="settings.common.is_root_ca" class="alert alert-warning">
            <i class="bi bi-shield-lock me-2"></i>
            <strong>Root CA Server Mode Active</strong>
            <p class="mb-2 mt-1">
              This instance is configured as a Root CA Server. Only subordinate CA certificates can be issued.
              Client and server certificates must be issued by importing subordinate CAs into other instances.
            </p>
            <small class="text-muted">
              <strong>Security Note:</strong> This setting should be changed carefully as it affects the fundamental operation of the certificate authority.
            </small>
          </div>
        </div>
      </div>

      <!-- Mail Section -->
      <h3>Mail</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3 row">
            <div class="col-9">
              <label for="mail-smtp-host" class="form-label">SMTP Host</label>
              <input
                  id="mail-smtp-host"
                  v-model="settings.mail.smtp_host"
                  type="text"
                  class="form-control"
              />
            </div>
            <div class="col-3">
              <label for="mail-smtp-port" class="form-label">Port</label>
              <input
                  id="mail-smtp-port"
                  v-model="settings.mail.smtp_port"
                  type="number"
                  class="form-control"
              />
            </div>
          </div>
          <div class="mb-3">
            <label for="mail-encryption" class="form-label">Role</label>
            <select
                id="mail-encryption"
                v-model="settings.mail.encryption"
                class="form-select"
            >
              <option :value="Encryption.None">None</option>
              <option :value="Encryption.TLS">TLS</option>
              <option :value="Encryption.STARTTLS">STARTTLS</option>
            </select>
          </div>
          <div class="mb-3">
            <label for="mail-username" class="form-label">Username</label>
            <input
                id="mail-username"
                v-model="settings.mail.username"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="mail-password" class="form-label">Password</label>
            <input
                id="mail-password"
                v-model="settings.mail.password"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="mail-from" class="form-label">From</label>
            <input
                id="mail-from"
                v-model="settings.mail.from"
                type="email"
                class="form-control"
            />
          </div>
        </div>
      </div>

      <!-- OIDC Section -->
      <h3>OIDC</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3">
            <label for="oidc-id" class="form-label">Client ID</label>
            <input
                id="oidc-id"
                v-model="settings.oidc.id"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-secret" class="form-label">Client Secret</label>
            <input
                id="oidc-secret"
                v-model="settings.oidc.secret"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-auth-url" class="form-label">Authorization URL</label>
            <input
                id="oidc-auth-url"
                v-model="settings.oidc.auth_url"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-callback-url" class="form-label">Callback URL</label>
            <input
                id="oidc-callback-url"
                v-model="settings.oidc.callback_url"
                type="text"
                class="form-control"
            />
          </div>
        </div>
      </div>
    </div>

    <h2>User</h2>
    <div class="card mt-3 mb-3">
      <div class="card-body">
        <h4 class="card-header">Change Password</h4>
        <form @submit.prevent="changePassword">
          <div v-if="authStore.current_user?.has_password" class="mb-3">
            <label for="old-password" class="form-label">Old Password</label>
            <input
                id="old-password"
                v-model="changePasswordReq.oldPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="new-password" class="form-label">New Password</label>
            <input
                id="new-password"
                v-model="changePasswordReq.newPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="confirm-password" class="form-label">Confirm New Password</label>
            <input
                id="confirm-password"
                v-model="confirmPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div v-if="password_error" class="alert alert-danger mt-3">
            {{ password_error }}
          </div>

          <button
              type="submit"
              class="btn btn-primary"
              :disabled="!canChangePassword"
          >
            Change Password
          </button>
        </form>
      </div>
      <div v-if="editableUser" class="card-body">
        <h4 class="card-header">Profile</h4>
        <div class="mb-3">
          <label for="user_name" class="form-label">Username</label>
          <input
              id="user_name"
              v-model="editableUser.name"
              type="text"
              class="form-control"
          />
        </div>
        <div class="mb-3">
          <label for="user_email" class="form-label">E-Mail</label>
          <input
              id="user_email"
              v-model="editableUser.email"
              type="email"
              class="form-control"
          />
        </div>
      </div>
    </div>

    <!-- Error Messages -->
    <div v-if="settings_error" class="alert alert-danger mt-3">
      {{ settings_error }}
    </div>
    <div v-if="user_error" class="alert alert-danger mt-3">
      {{ user_error }}
    </div>
    <div v-if="saved_successfully" class="alert alert-success mt-3">
      Settings saved successfully
    </div>

    <!-- Save Button -->
    <button class="btn btn-primary mt-3" @click="saveSettings">Save</button>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { type User, UserRole } from "@/types/User.ts";
import { useUserStore } from "@/stores/users.ts";
import { useSetupStore } from "@/stores/setup.ts";
import { Encryption, PasswordRule } from "@/types/Settings.ts";

// Stores
const settingsStore = useSettingsStore();
const authStore = useAuthStore();
const userStore = useUserStore();
const setupStore = useSetupStore();

// Computed state
const settings = computed(() => settingsStore.settings);
const current_user = computed(() => authStore.current_user);
const settings_error = computed(() => settingsStore.error);
const user_error = computed(() => userStore.error);
const password_error = computed(() => authStore.error);

const canChangePassword = computed(() =>
    changePasswordReq.value.newPassword === confirmPassword.value &&
    changePasswordReq.value.newPassword.length > 0
);

// Local state
const showPasswordDialog = ref(false);
const changePasswordReq = ref({ oldPassword: '', newPassword: '' });
const confirmPassword = ref('');
const editableUser = ref<User | null>(null);
const saved_successfully = ref(false);

// Methods
const changePassword = async () => {
  await authStore.changePassword(changePasswordReq.value.oldPassword, changePasswordReq.value.newPassword);
  showPasswordDialog.value = false;
  changePasswordReq.value = { oldPassword: '', newPassword: '' };
  confirmPassword.value = '';
};

const toggleRootCAMode = (event: Event) => {
  const isChecked = (event.target as HTMLInputElement).checked;

  if (isChecked) {
    // Enabling Root CA mode - show warning
    const confirmed = confirm(
      'WARNING: Enabling Root CA Server Mode\n\n' +
      'This will restrict your certificate authority to only issue subordinate CA certificates.\n\n' +
      '• Client certificates: CANNOT be issued from this instance\n' +
      '• Server certificates: CANNOT be issued from this instance\n' +
      '• Subordinate CA certificates: CAN be issued from this instance\n\n' +
      'You will need to use subordinate CAs from other instances to issue client/server certificates.\n\n' +
      'This setting takes effect after restart.\n\n' +
      'Are you sure you want to enable Root CA Server Mode?'
    );

    if (!confirmed) {
      event.preventDefault();
      // Revert the checkbox
      setTimeout(() => {
        settings.value!.common.is_root_ca = !isChecked;
      }, 0);
    }
  } else {
    // Disabling Root CA mode - show different warning
    const confirmed = confirm(
      'WARNING: Disabling Root CA Server Mode\n\n' +
      'This will allow your certificate authority to issue all types of certificates:\n\n' +
      '• Client certificates: CAN be issued\n' +
      '• Server certificates: CAN be issued\n' +
      '• CA certificates: CAN be issued directly\n\n' +
      'This setting takes effect after restart.\n\n' +
      'Are you sure you want to disable Root CA Server Mode?'
    );

    if (!confirmed) {
      event.preventDefault();
      // Revert the checkbox
      setTimeout(() => {
        settings.value!.common.is_root_ca = !isChecked;
      }, 0);
    }
  }
};

const saveSettings = async () => {
  saved_successfully.value = false;
  let success = true;

  if (current_user.value?.role === UserRole.Admin) {
    success &&= await settingsStore.saveSettings();
    await setupStore.reload();
  }

  if (editableUser.value) {
    success &&= await userStore.updateUser(editableUser.value);
    await authStore.fetchCurrentUser();
  }

  saved_successfully.value = success;
};

onMounted(async () => {
  if (authStore.isAdmin) {
    await settingsStore.fetchSettings();
  }
  if (current_user.value) {
    editableUser.value = { ...current_user.value };
  }
});

</script>

<style scoped>
.settings-tab {
  padding: var(--spacing-xl);
  background-color: var(--color-page-background);
  color: var(--color-text-primary);
  min-height: 100vh;
}

/* Dark mode form controls */
[data-theme="dark"] .settings-tab ::v-deep(.form-control) {
  background-color: var(--color-card);
  border-color: rgba(255, 255, 255, 0.1);
  color: var(--color-text-primary);
}

[data-theme="dark"] .settings-tab ::v-deep(.form-control:focus) {
  background-color: var(--color-card);
  border-color: var(--primary);
  color: var(--color-text-primary);
  box-shadow: 0 0 0 0.2rem rgba(66, 133, 244, 0.25);
}

[data-theme="dark"] .settings-tab ::v-deep(.form-select) {
  background-color: var(--color-card);
  border-color: rgba(255, 255, 255, 0.1);
  color: var(--color-text-primary);
}

[data-theme="dark"] .settings-tab ::v-deep(.form-select:focus) {
  background-color: var(--color-card);
  border-color: var(--primary);
  color: var(--color-text-primary);
  box-shadow: 0 0 0 0.2rem rgba(66, 133, 244, 0.25);
}

[data-theme="dark"] .settings-tab ::v-deep(.form-check-input:checked) {
  background-color: var(--primary);
  border-color: var(--primary);
}

/* Dark mode card styles */
[data-theme="dark"] .settings-tab ::v-deep(.card) {
  background-color: var(--color-card);
  border-color: rgba(255, 255, 255, 0.1);
  color: var(--color-text-primary);
}

[data-theme="dark"] .settings-tab ::v-deep(.card-header) {
  background-color: var(--color-hover);
  border-bottom-color: rgba(255, 255, 255, 0.1);
  color: var(--color-text-primary);
}

/* Dark mode text and labels */
[data-theme="dark"] .settings-tab ::v-deep(.form-label) {
  color: var(--color-text-primary);
}

[data-theme="dark"] .settings-tab ::v-deep(.form-check-label) {
  color: var(--color-text-primary);
}

/* Dark mode alerts */
[data-theme="dark"] .settings-tab ::v-deep(.alert-danger) {
  background-color: rgba(220, 53, 69, 0.1);
  border-color: rgba(220, 53, 69, 0.2);
  color: #ea868f;
}

[data-theme="dark"] .settings-tab ::v-deep(.alert-success) {
  background-color: rgba(25, 135, 84, 0.1);
  border-color: rgba(25, 135, 84, 0.2);
  color: #75b798;
}
</style>
