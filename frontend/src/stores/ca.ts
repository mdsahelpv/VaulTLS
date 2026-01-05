// CA store for managing Certificate Authority operations
import {defineStore} from 'pinia';
import type {CASummary, CADetails} from '@/types/Certificate';
import {fetchCAs, getCADetails, downloadCA, downloadCAKeyPair} from '@/api/certificates';

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
      const previousCAList = [...this.caList]; // Store previous state for rollback

      try {
        this.caList = await fetchCAs();
      } catch (error) {
        // Rollback: restore previous state
        this.caList = previousCAList;
        this.error = 'Failed to fetch CA list';
        console.error('Error fetching CA list:', error);
        throw error;
      } finally {
        this.loading = false;
      }
    },

    async fetchCADetails() {
      this.loading = true;
      this.error = null;
      const previousCADetails = this.currentCADetails; // Store previous state for rollback

      try {
        this.currentCADetails = await getCADetails();
      } catch (error) {
        // Rollback: restore previous state
        this.currentCADetails = previousCADetails;
        this.error = 'Failed to fetch CA details';
        console.error('Error fetching CA details:', error);
        throw error;
      } finally {
        this.loading = false;
      }
    },

    async downloadCACertificate() {
      try {
        await downloadCA();
      } catch (error) {
        this.error = 'Failed to download CA certificate';
        console.error('Error downloading CA certificate:', error);
        throw error;
      }
    },

    async downloadCAKeyPair() {
      try {
        await downloadCAKeyPair();
      } catch (error) {
        this.error = 'Failed to download CA key pair';
        console.error('Error downloading CA key pair:', error);
        throw error;
      }
    },

    clearError() {
      this.error = null;
    },
  },
});
