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
}

.container-fluid {
  margin-left: 240px;
  padding: var(--spacing-xl);
  transition: margin-left var(--transition-normal);
  background-color: transparent;
}

.content-shifted {
  margin-left: 240px !important;
}

@media (max-width: 991.98px) {
  .container-fluid {
    margin-left: 0;
    padding: var(--spacing-lg);
  }
}

@media (min-width: 992px) {
  .container-fluid {
    max-width: 100%;
  }
}

</style>
