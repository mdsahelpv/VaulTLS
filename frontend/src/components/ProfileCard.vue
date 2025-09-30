<template>
  <div class="card text-center shadow-sm">
    <div class="card-body">
      <Avatar
          :size="100"
          :name="authStore.current_user?.name || 'User'"
          variant="bauhaus"
          :colors=avatarColors
          class="rounded-circle img-thumbnail mb-3"
      />
      <h5 class="card-title">{{ authStore.current_user?.name }}</h5>
      <p class="card-text text-muted email">{{ formatEmail(authStore.current_user?.email) }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useAuthStore } from "@/stores/auth.ts";
import Avatar from 'vue-boring-avatars';

const formatEmail = (email?: string) => {
  return email?.replace('@', '\u200B@');
};

const avatarColors = [
  'var(--color-avatar-1)',
  'var(--color-avatar-2)',
  'var(--color-avatar-3)',
  'var(--color-avatar-4)',
  'var(--color-avatar-5)'
];

const authStore = useAuthStore();
</script>

<style scoped>
.card {
  max-width: 220px;
  margin: var(--spacing-md);
  background-color: var(--color-card);
  border: none;
  border-radius: var(--radius-lg);
  padding: var(--spacing-lg);
  box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.05), 0 2px 10px var(--shadow-color);
  transition: box-shadow var(--transition-fast);
}

.card:hover {
  box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.1), 0 4px 16px var(--shadow-color);
}
</style>
