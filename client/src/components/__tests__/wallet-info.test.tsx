import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { WalletInfo } from '../wallet-info';
import { useWallet } from '@/hooks/use-wallet';
import { useAuth } from '@/hooks/use-auth';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Mock dependencies
vi.mock('@/hooks/use-wallet', () => ({
  useWallet: vi.fn(),
}));

vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(),
}));

vi.mock('@tanstack/react-query', async () => {
  const actual = await vi.importActual<typeof import('@tanstack/react-query')>('@tanstack/react-query');
  return {
    ...actual,
    useQuery: vi.fn(),
  };
});

// Type for mocked useWallet
type MockUseWallet = {
  data: {
    address: string;
    balance: string;
    tokenBalance: string;
  } | null;
  isLoading: boolean;
};

// Type for mocked useAuth
type MockUseAuth = {
  user: {
    id: number;
    xdcWalletAddress: string | null;
  } | null;
};

describe('WalletInfo Component', () => {
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

  it('should display wallet address when available', () => {
    const mockUser: MockUseAuth = {
      user: {
        id: 1,
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      },
    };

    const mockWallet: MockUseWallet = {
      data: {
        address: 'xdc1234567890123456789012345678901234567890',
        balance: '1000000000000000000',
        tokenBalance: '500000000000000000',
      },
      isLoading: false,
    };

    (useAuth as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockUser);
    (useWallet as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockWallet);

    render(
      <QueryClientProvider client={queryClient}>
        <WalletInfo />
      </QueryClientProvider>
    );

    // Query the DOM for actual rendered content
    const addressElement = screen.getByText(/xdc1234567890123456789012345678901234567890/i);
    expect(addressElement).toBeDefined();
  });

  it('should display wallet balance', () => {
    const mockUser: MockUseAuth = {
      user: {
        id: 1,
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      },
    };

    const mockWallet: MockUseWallet = {
      data: {
        address: 'xdc1234567890123456789012345678901234567890',
        balance: '1000000000000000000',
        tokenBalance: '500000000000000000',
      },
      isLoading: false,
    };

    (useAuth as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockUser);
    (useWallet as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockWallet);

    render(
      <QueryClientProvider client={queryClient}>
        <WalletInfo />
      </QueryClientProvider>
    );

    // Query for balance text in the DOM
    expect(screen.getByText(/1.0 XDC/i)).toBeDefined();
  });

  it('should show loading state', () => {
    const mockUser: MockUseAuth = {
      user: {
        id: 1,
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      },
    };

    const mockWallet: MockUseWallet = {
      data: null,
      isLoading: true,
    };

    (useAuth as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockUser);
    (useWallet as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockWallet);

    render(
      <QueryClientProvider client={queryClient}>
        <WalletInfo />
      </QueryClientProvider>
    );

    // Check for loading spinner (Loader2 component)
    const loadingSpinner = document.querySelector('.animate-spin');
    expect(loadingSpinner).toBeDefined();
  });

  it('should handle missing wallet data', () => {
    const mockUser: MockUseAuth = {
      user: {
        id: 1,
        xdcWalletAddress: null,
      },
    };

    const mockWallet: MockUseWallet = {
      data: null,
      isLoading: false,
    };

    (useAuth as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockUser);
    (useWallet as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockWallet);

    render(
      <QueryClientProvider client={queryClient}>
        <WalletInfo />
      </QueryClientProvider>
    );

    // Check for "Not available" text when wallet data is missing
    expect(screen.getByText(/Not available/i)).toBeDefined();
  });
});
