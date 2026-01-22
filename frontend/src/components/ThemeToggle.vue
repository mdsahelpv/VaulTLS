<template>
  <div
    class="theme-toggle-slide"
    :class="{ 'dark-mode': isDark }"
    :title="isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'"
    tabindex="0"
    role="button"
    :aria-pressed="isDark"
    @click="toggleTheme"
    @keydown.enter="toggleTheme"
    @keydown.space.prevent="toggleTheme"
  >
    <div class="toggle-track">
      <div
        class="toggle-thumb"
        :class="{ 'dark': isDark }"
      >
        <i
          :class="iconClass"
          class="toggle-icon"
        />
      </div>
      <div class="toggle-labels">
        <span class="toggle-label">{{ isDark ? '' : '☀️' }}</span>
        <span class="toggle-label">{{ isDark ? '🌙' : '' }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useThemeStore } from '@/stores/theme'

const themeStore = useThemeStore()

const isDark = computed(() => themeStore.isDark)
const iconClass = computed(() => isDark.value ? 'bi bi-moon' : 'bi bi-sun')

const toggleTheme = () => {
  themeStore.toggleTheme()
}
</script>

<style scoped>
.theme-toggle-slide {
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 70px;
  height: 35px;
  border-radius: 17.5px;
  background: var(--color-card);
  border: 1px solid var(--sidebar-border);
  box-shadow: 0 1px 3px var(--shadow-color);
  transition: all var(--transition-fast);
  outline: none;
}

.theme-toggle-slide:hover {
  background: var(--color-hover);
  box-shadow: 0 2px 6px var(--shadow-color);
}

.theme-toggle-slide:focus-visible {
  box-shadow: 0 0 0 2px var(--primary);
}

.theme-toggle-slide.dark-mode {
  background: #000000;
}

.theme-toggle-slide.dark-mode:hover {
  background: #1a1a1a;
}

.toggle-track {
  position: relative;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 4px;
}

.toggle-thumb {
  position: absolute;
  width: 27px;
  height: 27px;
  background: #ffffff;
  border-radius: 50%;
  transition: all var(--transition-normal);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  left: 4px;
  top: 4px;
}

.toggle-thumb.dark {
  left: 39px;
  background: var(--color-card);
}

.toggle-icon {
  font-size: 13px;
  color: #333333;
  transition: all var(--transition-normal);
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%) translateX(3px);
}

.toggle-thumb.dark .toggle-icon {
  color: #ffffff;
}

.toggle-labels {
  position: absolute;
  left: 0;
  right: 0;
  top: 0;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 8px;
  pointer-events: none;
}

.toggle-label {
  font-size: 12px;
  line-height: 1;
  transition: all var(--transition-normal);
}
</style>
