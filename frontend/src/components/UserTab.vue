// src/components/UserTab.vue
<template>
  <div class="user-container">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h1>Users</h1>
      <div class="d-flex gap-2">
        <button
          class="btn btn-primary"
          @click="isCreateModalVisible = true"
        >
          Create New User
        </button>
      </div>
    </div>

    <div class="card">
      <div class="card-body p-0">
        <!-- Loading and Error states inside card -->
        <div v-if="userStore.loading" class="alert alert-info m-3">
          Loading...
        </div>
        <div v-else-if="userStore.error" class="alert alert-danger m-3">
          {{ userStore.error }}
        </div>
        <!-- Users Table -->
        <div v-else class="table-responsive">
          <table class="table table-hover mb-0">
            <thead class="table-light">
              <tr>
                <th>Username</th>
                <th>E-Mail</th>
                <th>Role</th>
                <th>Actions</th>
              </tr>
            </thead>
        <tbody>
          <tr v-for="user in userStore.users" :key="user.id">
            <td :id="'UserName-' + user.id">{{ user.name }}</td>
            <td :id="'UserMail-' + user.id">{{ user.email }}</td>
            <td :id="'UserRole-' + user.id">{{ UserRole[user.role] }}</td>
            <td>
              <button
                :id="'UserDeletebutton-' + user.id"
                class="btn btn-danger btn-sm"
                @click="confirmDeleteUser(user)"
              >
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>
        </div>
      </div>
    </div>

    <!-- Create User Modal -->
    <div 
      class="modal fade" 
      :class="{ 'show d-block': isCreateModalVisible }"
      tabindex="-1"
      v-if="isCreateModalVisible"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Create New User</h5>
            <button 
              type="button" 
              class="btn-close" 
              @click="isCreateModalVisible = false"
            ></button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="handleCreateUser">
              <div class="mb-3">
                <label for="user_name" class="form-label">Username</label>
                <input 
                  type="text" 
                  class="form-control" 
                  id="user_name"
                  v-model="newUser.user_name"
                  required
                >
              </div>
              <div class="mb-3">
                <label for="user_email" class="form-label">E-Mail</label>
                <input
                    type="text"
                    class="form-control"
                    id="user_email"
                    v-model="newUser.user_email"
                    required
                >
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input 
                  type="password" 
                  class="form-control" 
                  id="password"
                  v-model="newUser.password"
                >
              </div>
              <div class="mb-3">
                <label for="user_role" class="form-label">Role</label>
                <select
                    class="form-select"
                    id="user_role"
                    v-model="newUser.role"
                    required
                >
                  <option :value="UserRole.User">User</option>
                  <option :value="UserRole.Admin">Admin</option>
                </select>
              </div>

              <div class="modal-footer">
                <button 
                  type="button" 
                  class="btn btn-secondary" 
                  @click="isCreateModalVisible = false"
                >
                  Cancel
                </button>
                <button type="submit" class="btn btn-primary">
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
    <!-- Modal Backdrop -->
    <div 
      class="modal-backdrop fade show" 
      v-if="isCreateModalVisible"
    ></div>

    <!-- Delete Confirmation Modal -->
    <div
        v-if="isDeleteModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Delete User</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>
              Are you sure you want to delete the user
              <strong>{{ userToDelete?.name }}</strong>?
            </p>
            <p class="text-warning">
              <small>
                Disclaimer: Deleting the user will also delete their certificates. The certificates are still valid until expiry.
              </small>
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              Cancel
            </button>
            <button type="button" class="btn btn-danger" @click="deleteUser">
              Delete
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { type CreateUserRequest, UserRole, type User } from '@/types/User';
import { useUserStore } from '@/stores/users.ts';
import { useCertificateStore } from '@/stores/certificates.ts';

// Stores
const userStore = useUserStore();

// Local state
const isCreateModalVisible = ref(false);
const isDeleteModalVisible = ref(false);
const userToDelete = ref<User | null>(null);
const newUser = ref<CreateUserRequest>({
  user_name: '',
  user_email: '',
  password: '',
  role: UserRole.User,
});

// Lifecycle hook
onMounted(async () => {
  await userStore.fetchUsers();
});

// Methods
const handleCreateUser = async () => {
  await userStore.createUser(newUser.value);
  isCreateModalVisible.value = false;
  // Reset form
  newUser.value = {
    user_name: '',
    user_email: '',
    password: '',
    role: UserRole.User,
  };
};

const confirmDeleteUser = async (user: User) => {
  userToDelete.value = user;
  isDeleteModalVisible.value = true;
};

const closeDeleteModal = () => {
  userToDelete.value = null;
  isDeleteModalVisible.value = false;
};

const deleteUser = async () => {
  if (userToDelete.value) {
    await userStore.deleteUser(userToDelete.value.id);
    const certStore = useCertificateStore();
    await certStore.fetchCertificates();
    closeDeleteModal();
  }
};
</script>


<style scoped>
.user-container {
  padding: 20px;
  background-color: transparent;
}

.card {
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  border: 1px solid #e9ecef;
}

.card-header {
  background-color: #f8f9fa;
  border-bottom: 1px solid #e9ecef;
}

.table th {
  border-top: none;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.875rem;
  letter-spacing: 0.025em;
}

.table-hover tbody tr:hover {
  background-color: rgba(0, 0, 123, 0.075);
}

.table-responsive {
  border-radius: var(--radius-md);
  overflow: hidden;
}

:deep(.modal.show) {
  background-color: rgba(0, 0, 0, 0.5);
}

@media (max-width: 768px) {
  .user-container {
    padding: 10px;
  }
}
</style>
