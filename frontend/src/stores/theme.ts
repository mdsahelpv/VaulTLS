import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export type Theme = 'light' | 'dark'

export const useThemeStore = defineStore('theme', () => {
  // Get stored theme or default to 'light'
  const getStoredTheme = (): Theme => {
    const stored = localStorage.getItem('vaultls-theme')
    return (stored === 'dark' || stored === 'light') ? stored : 'light'
  }

  // Reactive state
  const currentTheme = ref<Theme>(getStoredTheme())

  // Computed property to check if dark
  const isDark = ref<boolean>(currentTheme.value === 'dark')

  // Method to toggle theme
  const toggleTheme = () => {
    currentTheme.value = currentTheme.value === 'light' ? 'dark' : 'light'
    isDark.value = currentTheme.value === 'dark'
  }

  // Method to set specific theme
  const setTheme = (theme: Theme) => {
    currentTheme.value = theme
    isDark.value = theme === 'dark'
  }

  // Watch for changes and update DOM + localStorage
  watch(currentTheme, (newTheme) => {
    // Update DOM attribute
    document.documentElement.setAttribute('data-theme', newTheme)

    // Store in localStorage
    localStorage.setItem('vaultls-theme', newTheme)

    // Update isDark computed
    isDark.value = newTheme === 'dark'
  }, { immediate: true })

  // Initialize theme on store creation
  const init = () => {
    const theme = getStoredTheme()
    document.documentElement.setAttribute('data-theme', theme)
    currentTheme.value = theme
    isDark.value = theme === 'dark'
  }

  return {
    currentTheme,
    isDark,
    toggleTheme,
    setTheme,
    init
  }
})
