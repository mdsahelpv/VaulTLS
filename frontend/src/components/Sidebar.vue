<template>
  <div>
    <!-- Always visible toggle button when sidebar is hidden -->
    <button
        v-if="!visible"
        class="sidebar-toggle btn btn-primary d-lg-none"
        @click="toggleSidebar"
        :style="{ left: '10px' }"
    >
      <i class="bi bi-list"></i>
    </button>

    <!-- Sidebar Backdrop (Mobile Only) -->
    <div
        class="sidebar-backdrop"
        :class="{ 'd-block': visible && isMobile }"
        @click="toggleSidebar"
    ></div>

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
          <li v-if="isAdmin" class="nav-item mb-2">
            <a
                href="#"
                class="nav-link d-flex align-items-center gap-2"
                :class="{ active: activeRouteName === 'Users' }"
                @click.prevent="goToRoute('Users')"
            >
              Users
            </a>
          </li>
          <li v-if="isAdmin" class="nav-item mb-2">
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
  width: 240px;
  height: 100vh;
  overflow-y: auto;
  z-index: 1000;
  background-color: var(--color-background);
  border-right: 1px solid rgba(0, 0, 0, 0.08);
  font-family: var(--font-family);
  transition: transform var(--transition-normal);
}

.sidebar-toggle {
  position: fixed;
  bottom: 20px;
  left: 20px;
  width: 48px;
  height: 48px;
  border-radius: var(--radius-lg);
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: var(--color-card);
  border: 1px solid rgba(0, 0, 0, 0.1);
  color: var(--color-text-primary);
  z-index: 1001;
  transition: all var(--transition-fast);
  box-shadow: 0 2px 12px var(--shadow-color);
}

.sidebar-toggle:hover {
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
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.2);
  backdrop-filter: blur(4px);
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

.nav-link {
  color: var(--color-text-primary);
  text-decoration: none;
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--radius-md);
  font-weight: var(--font-weight-normal);
  font-size: 14px;
  letter-spacing: -0.025em;
  transition: all var(--transition-fast);
  position: relative;
}

.nav-link::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 0;
  background-color: var(--primary);
  border-radius: var(--radius-md);
  transition: width var(--transition-fast);
}

.nav-link:hover {
  background-color: var(--color-hover);
}

.nav-link.active {
  background-color: var(--color-active);
}

.nav-link.active::before {
  width: 3px;
}

.logout-link {
  color: var(--danger);
  font-weight: var(--font-weight-medium);
}

.version-info {
  font-size: 12px;
  font-weight: var(--font-weight-medium);
  opacity: 0.6;
}

.flex-grow-1 {
  padding: var(--spacing-lg) var(--spacing-md);
}

.p-3 {
  padding: var(--spacing-md);
}

.theme-toggle-container {
  display: flex;
  justify-content: center;
  align-items: center;
}
</style>
