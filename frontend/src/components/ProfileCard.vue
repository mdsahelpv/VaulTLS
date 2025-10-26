<template>
  <div class="card text-center shadow-sm">
    <div class="card-body">
      <div class="avatar-circle mb-3" :style="avatarStyle">
        {{ firstLetter }}
      </div>
      <h5 class="card-title">{{ authStore.current_user?.name }}</h5>
      <p class="card-text text-muted email">{{ formatEmail(authStore.current_user?.email) }}</p>
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

const avatarColors = [
  'var(--color-avatar-1)',
  'var(--color-avatar-2)',
  'var(--color-avatar-3)',
  'var(--color-avatar-4)',
  'var(--color-avatar-5)'
];

// Generate a consistent background color for each user based on their name
const avatarStyle = computed(() => {
  const name = userName.value;
  // Simple hash to get consistent color for each username
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash) + name.charCodeAt(i);
    hash = hash & hash; // Convert to 32-bit integer
  }
  const colorIndex = Math.abs(hash) % avatarColors.length;
  return {
    backgroundColor: 'var(--color-card)',
    color: 'var(--color-text-primary)',
    width: '100px',
    height: '100px',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '3.2rem',
    fontWeight: '300',
    letterSpacing: '-0.05em',
    margin: '0 auto',
    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.12), 0 2px 8px rgba(0, 0, 0, 0.06), inset 0 1px 0 rgba(255, 255, 255, 0.1)',
    border: '0',
    background: 'linear-gradient(145deg, var(--color-card) 0%, rgba(255, 255, 255, 0.05) 50%, var(--color-card) 100%)',
    fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    backgroundClip: 'content-box',
    content: 'close-quote',
    lineHeight: '1',
    position: 'relative',
    transition: 'transform 0.2s ease, box-shadow 0.2s ease'
  };
});
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
