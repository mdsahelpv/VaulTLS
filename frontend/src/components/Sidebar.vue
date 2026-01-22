<template>
  <div>
    <!-- Always visible toggle button when sidebar is hidden -->
    <button
      v-if="!visible"
      class="sidebar-toggle btn btn-primary d-lg-none"
      :style="{ left: '10px' }"
      @click="toggleSidebar"
    >
      <i class="bi bi-list" />
    </button>

    <!-- Sidebar Backdrop (Mobile Only) -->
    <div
      class="sidebar-backdrop"
      :class="{ 'd-block': visible && isMobile }"
      @click="toggleSidebar"
    />

    <!-- Sidebar Content -->
    <div
      class="sidebar shadow-lg rounded-end d-flex flex-column"
      :class="{ 'sidebar-visible': visible, 'sidebar-hidden': !visible }"
    >
      <ProfileCard />

      <!-- Theme Toggle -->
      <div class="theme-toggle-container py-2">
        <ThemeToggle />
      </div>

      <div class="flex-grow-1 overflow-auto mt-4">
        <ul class="nav flex-column flex-grow-1">
          <li class="nav-item mb-2">
            <a
              href="#"
              class="nav-link d-flex align-items-center gap-2"
              :class="{ active: activeRouteName === 'Overview' }"
              @click.prevent="goToRoute('Overview')"
            >
              Overview
            </a>
          </li>
          <li class="nav-item mb-2">
            <a
              href="#"
              class="nav-link d-flex align-items-center gap-2"
              :class="{ active: activeRouteName === 'CA' }"
              @click.prevent="goToRoute('CA')"
            >
              CA Tools
            </a>
          </li>
          <li
            v-if="isAdmin"
            class="nav-item mb-2"
          >
            <a
              href="#"
              class="nav-link d-flex align-items-center gap-2"
              :class="{ active: activeRouteName === 'Users' }"
              @click.prevent="goToRoute('Users')"
            >
              Users
            </a>
          </li>
          <li
            v-if="isAdmin"
            class="nav-item mb-2"
          >
            <a
              href="#"
              class="nav-link d-flex align-items-center gap-2"
              :class="{ active: activeRouteName === 'CRL' }"
              @click.prevent="goToRoute('CRL')"
            >
              CRL / OCSP
            </a>
          </li>
          <li
            v-if="isAdmin"
            class="nav-item mb-2"
          >
            <a
              href="#"
              class="nav-link d-flex align-items-center gap-2"
              :class="{ active: activeRouteName === 'Audit' }"
              @click.prevent="goToRoute('Audit')"
            >
              Audit Logs
            </a>
          </li>

          <li class="nav-item">
            <a
              href="#"
              class="nav-link d-flex align-items-center gap-2"
              :class="{ active: activeRouteName === 'Settings' }"
              @click.prevent="goToRoute('Settings')"
            >
              Settings
            </a>
          </li>
        </ul>
      </div>
      <div class="p-3">
        <a
          href="#"
          class="nav-link logout-link d-flex align-items-center gap-2"
          @click="handleLogout"
        >
          Logout
        </a>
      </div>
      <div class="text-center text-muted small p-2 version-info">
        {{ "Version: " + setupStore.version }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import ProfileCard from './ProfileCard.vue';
import ThemeToggle from './ThemeToggle.vue';
import { UserRole } from "@/types/User.ts";
import { useAuthStore } from "@/stores/auth.ts";
import {useSettingsStore} from "@/stores/settings.ts";
import {useSetupStore} from "@/stores/setup.ts";
defineProps({
  currentTab: String,
  visible: Boolean
});
const emit = defineEmits(['change-tab', 'toggle-sidebar']);

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const setupStore = useSetupStore();
const isMobile = ref(false);

const activeRouteName = computed(() => route.name);
const isAdmin = computed(() => authStore.current_user?.role === UserRole.Admin);

const goToRoute = (name: string) => {
  emit('change-tab', name);
  router.push({ name });
};

const handleLogout = async () => {
  await authStore.logout();
  goToRoute('Login');
};

const toggleSidebar = () => {
  emit('toggle-sidebar');
};

const checkIfMobile = () => {
  isMobile.value = window.innerWidth < 992;
};

onMounted(async () => {
  checkIfMobile();
  window.addEventListener('resize', checkIfMobile);
});
</script>

<style scoped>
.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  width: var(--sidebar-width);
  height: 100vh;
  z-index: 1000;
  background-color: var(--color-background);
  border-right: 1px solid var(--color-border);
  font-family: var(--font-family);
  transition: transform var(--transition-normal);
  display: flex;
  flex-direction: column;
}

.sidebar-toggle {
  position: fixed;
  top: 20px;
  right: 20px;
  width: 44px;
  height: 44px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: var(--color-background);
  border: 1px solid var(--color-border);
  color: var(--color-text-primary);
  z-index: 1001;
  transition: all var(--transition-fast);
  box-shadow: var(--shadow-sm);
}

.sidebar-toggle:hover {
  background-color: var(--color-hover);
  transform: scale(1.05);
}

.sidebar-visible {
  transform: translateX(0);
}

.sidebar-hidden {
  transform: translateX(-100%);
}

.sidebar-backdrop {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background-color: rgba(0, 0, 0, 0.4);
  backdrop-filter: blur(8px);
  z-index: 999;
  transition: opacity var(--transition-normal);
}

@media (min-width: 992px) {
  .sidebar {
    transform: translateX(0) !important;
  }
  .sidebar-toggle {
    display: none !important;
  }
}

.nav {
  padding: var(--spacing-md);
}

.nav-link {
  color: var(--color-text-primary);
  text-decoration: none;
  padding: 10px 16px;
  border-radius: var(--radius-md);
  font-weight: var(--font-weight-medium);
  font-size: 14px;
  transition: all var(--transition-fast);
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.nav-link i {
  font-size: 1.1em;
  opacity: 0.7;
}

.nav-link:hover {
  background-color: var(--color-hover);
  color: var(--primary);
}

.nav-link.active {
  background-color: var(--color-active);
  color: var(--primary);
}

.nav-link.active i {
  opacity: 1;
}

.logout-link {
  color: var(--danger) !important;
  margin-top: auto;
  font-weight: var(--font-weight-semibold);
}

.logout-link:hover {
  background-color: rgba(255, 59, 48, 0.08);
}

.version-info {
  font-size: 11px;
  color: var(--color-text-secondary);
  text-align: center;
  padding: var(--spacing-md);
  opacity: 0.6;
}

.theme-toggle-container {
  padding: var(--spacing-md);
  display: flex;
  justify-content: center;
  align-items: center;
}

.flex-grow-1 {
  overflow-y: auto;
  scrollbar-width: thin;
}
</style>
