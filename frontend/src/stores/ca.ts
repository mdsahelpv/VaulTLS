// CA store - simplified for now since main functionality is in CATools component
import {defineStore} from 'pinia';
import type {CASummary, CADetails} from '@/types/Certificate';
import {fetchCAs} from '@/api/certificates';

export const useCAStore = defineStore('ca', {
  state: () => ({
    caList: [] as CASummary[],
    currentCADetails: null as CADetails | null,
    loading: false,
    error: null as string | null,
  }),

  actions: {
    async fetchCAList() {
      this.loading = true;
      this.error = null;
      try {
        // Simplified for now - could be extended later if needed
        this.caList = [];
      } catch (error) {
        this.error = 'Failed to fetch CA list';
        console.error('Error fetching CA list:', error);
      } finally {
        this.loading = false;
      }
    },

    async fetchCADetails() {
      // Simplified - could be implemented if needed
      this.currentCADetails = null;
    },
  },
});
