import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from '../use-auth';
import api from '@/lib/api';
import csrfService from '@/lib/csrf';

// Mock dependencies
vi.mock('@/lib/api', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

vi.mock('@/lib/csrf', () => ({
  default: {
    fetchToken: vi.fn().mockResolvedValue(undefined),
  },
}));

describe('useAuth Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should fetch user on mount', async () => {
    const mockUser = {
      id: 1,
      username: 'testuser',
      email: 'test@example.com',
      githubId: '123',
      githubUsername: 'testuser',
      isProfileComplete: true,
      xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      role: 'contributor' as const,
      promptBalance: 100,
    };

    (api.get as any).mockResolvedValue(mockUser);

    const { result } = renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.user).toEqual(mockUser);
    expect(api.get).toHaveBeenCalledWith('/api/auth/user');
  });

  it('should handle unauthenticated state', async () => {
    (api.get as any).mockResolvedValue(null);

    const { result } = renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.user).toBeNull();
  });

  it('should handle fetch error', async () => {
    (api.get as any).mockRejectedValue(new Error('Network error'));

    const { result } = renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.user).toBeNull();
    expect(result.current.error).toBeDefined();
  });

  it('should sign out user', async () => {
    const mockUser = {
      id: 1,
      username: 'testuser',
    };

    (api.get as any).mockResolvedValue(mockUser);
    (api.post as any).mockResolvedValue({ success: true });

    const { result } = renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });

    await waitFor(() => {
      expect(result.current.user).toBeDefined();
    });

    await result.current.signOut();

    expect(api.post).toHaveBeenCalledWith('/api/auth/logout');
    expect(result.current.user).toBeNull();
  });

  it('should refetch user data', async () => {
    const mockUser = {
      id: 1,
      username: 'testuser',
    };

    (api.get as any).mockResolvedValue(mockUser);

    const { result } = renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });

    await waitFor(() => {
      expect(result.current.user).toBeDefined();
    });

    vi.clearAllMocks();
    (api.get as any).mockResolvedValue({ ...mockUser, username: 'updateduser' });

    await result.current.refetch();

    expect(api.get).toHaveBeenCalledWith('/api/auth/user');
  });

  it('should fetch CSRF token for authenticated users', async () => {
    const mockUser = {
      id: 1,
      username: 'testuser',
    };

    (api.get as any).mockResolvedValue(mockUser);

    renderHook(() => useAuth(), {
      wrapper: AuthProvider,
    });

    await waitFor(() => {
      expect(csrfService.fetchToken).toHaveBeenCalled();
    });
  });
});


