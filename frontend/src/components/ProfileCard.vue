<template>
  <div class="profile-card">
    <div class="avatar-circle">
      {{ firstLetter }}
    </div>
    <div class="profile-info">
      <div class="profile-name">{{ authStore.current_user?.name }}</div>
      <div class="profile-email">{{ formatEmail(authStore.current_user?.email) }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useAuthStore } from "@/stores/auth.ts";

const authStore = useAuthStore();

const formatEmail = (email?: string) => {
  return email?.replace('@', '\u200B@');
};

const userName = computed(() => authStore.current_user?.name || 'User');
const firstLetter = computed(() => userName.value.charAt(0).toUpperCase());
</script>

<style scoped>
.profile-card {
  padding: var(--spacing-lg) var(--spacing-md);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-md);
  text-align: center;
}

.avatar-circle {
  width: 72px;
  height: 72px;
  border-radius: 50%;
  background: var(--color-active);
  color: var(--primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 28px;
  font-weight: var(--font-weight-bold);
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--color-border);
}

.profile-name {
  font-weight: var(--font-weight-semibold);
  font-size: 16px;
  color: var(--color-text-primary);
  line-height: 1.2;
}

.profile-email {
  font-size: 12px;
  color: var(--color-text-secondary);
  word-break: break-all;
  margin-top: 4px;
}
</style>
