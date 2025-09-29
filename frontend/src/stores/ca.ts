import {defineStore} from 'pinia';
import type {CASummary, CADetails} from '@/types/Certificate';
import {fetchCAList, fetchCADetails} from '@/api/certificates';

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
        this.caList = await fetchCAList();
      } catch (error) {
        this.error = 'Failed to fetch CA list';
        console.error('Error fetching CA list:', error);
      } finally {
        this.loading = false;
      }
    },

    async fetchCADetails() {
      this.loading = true;
      this.error = null;
      try {
        this.currentCADetails = await fetchCADetails();
      } catch (error) {
        this.error = 'Failed to fetch CA details';
        console.error('Error fetching CA details:', error);
      } finally {
        this.loading = false;
      }
    },
  },
});
