<template>
  <div class="d-flex">
    <!-- Sidebar -->
    <Sidebar
        :currentTab="currentTab"
        :visible="sidebarVisible"
        @toggle-sidebar="toggleSidebar"
        @change-tab="setTab"
    />

    <!-- Main Content -->
    <div class="container-fluid mt-4 flex-grow-1" :class="{ 'content-shifted': sidebarVisible }">
      <router-view />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import Sidebar from '@/components/Sidebar.vue';

const currentTab = ref('Overview');
const sidebarVisible = ref(false);

const setTab = (tab: string) => {
  currentTab.value = tab;
  // Close sidebar on mobile when a tab is selected
  if (window.innerWidth < 992) {
    sidebarVisible.value = false;
  }
};

const toggleSidebar = () => {
  sidebarVisible.value = !sidebarVisible.value;
};

// Close sidebar when window is resized to desktop size
watch(() => window.innerWidth, (width) => {
  if (width >= 992) {
    sidebarVisible.value = false;
  }
});
</script>

<style scoped>
.d-flex {
  min-height: 100vh;
  background-color: var(--color-page-background);
  font-family: var(--font-family);
  overflow-x: hidden;
}

.container-fluid {
  margin-left: var(--sidebar-width);
  padding: var(--spacing-xxl);
  transition: all var(--transition-normal);
  background-color: transparent;
  min-height: 100vh;
}

.content-shifted {
  margin-left: var(--sidebar-width) !important;
}

/* Page Transition */
.v-enter-active,
.v-leave-active {
  transition: opacity var(--transition-normal), transform var(--transition-normal);
}

.v-enter-from,
.v-leave-to {
  opacity: 0;
  transform: translateY(10px);
}

@media (max-width: 991.98px) {
  .container-fluid {
    margin-left: 0;
    padding: var(--spacing-lg);
    padding-top: var(--spacing-xxl);
  }
}

@media (min-width: 992px) {
  .container-fluid {
    /* Removed max-width constraint for full-width usage */
  }
}
</style>
