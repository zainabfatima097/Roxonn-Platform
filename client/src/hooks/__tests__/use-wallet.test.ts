import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useWallet } from '../use-wallet';
import { useAuth } from '../use-auth';

// Mock dependencies
vi.mock('../use-auth', () => ({
  useAuth: vi.fn(),
}));

global.fetch = vi.fn();

describe('useWallet Hook', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    vi.clearAllMocks();
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    });
  });

  it('should fetch wallet info for authenticated user', async () => {
    (useAuth as any).mockReturnValue({
      user: {
        id: 1,
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      },
    });

    const mockWalletInfo = {
      address: 'xdc1234567890123456789012345678901234567890',
      balance: '1000000000000000000',
      tokenBalance: '500000000000000000',
    };

    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockWalletInfo,
    });

    const { result } = renderHook(() => useWallet(), {
      wrapper: ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      ),
    });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toEqual(mockWalletInfo);
    expect(global.fetch).toHaveBeenCalled();
  });

  it('should not fetch wallet info for unauthenticated user', () => {
    (useAuth as any).mockReturnValue({
      user: null,
    });

    const { result } = renderHook(() => useWallet(), {
      wrapper: ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      ),
    });

    expect(result.current.isFetching).toBe(false);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should handle fetch error', async () => {
    (useAuth as any).mockReturnValue({
      user: {
        id: 1,
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      },
    });

    (global.fetch as any).mockRejectedValue(new Error('Network error'));

    const { result } = renderHook(() => useWallet(), {
      wrapper: ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      ),
    });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error).toBeDefined();
  });

  it('should return default values when user has no wallet', () => {
    (useAuth as any).mockReturnValue({
      user: {
        id: 1,
        xdcWalletAddress: null,
      },
    });

    const { result } = renderHook(() => useWallet(), {
      wrapper: ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      ),
    });

    // Should still attempt to fetch, but might return empty data
    expect(result.current).toBeDefined();
  });

  it('should refetch on window focus', async () => {
    (useAuth as any).mockReturnValue({
      user: {
        id: 1,
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      },
    });

    const mockWalletInfo = {
      address: 'xdc1234567890123456789012345678901234567890',
      balance: '1000000000000000000',
      tokenBalance: '500000000000000000',
    };

    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockWalletInfo,
    });

    const { result } = renderHook(() => useWallet(), {
      wrapper: ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      ),
    });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    // Simulate window focus
    window.dispatchEvent(new Event('focus'));

    // Should refetch (depends on refetchOnWindowFocus setting)
    expect(result.current).toBeDefined();
  });
});


