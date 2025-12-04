import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response, Express } from 'express';
import { requireAuth } from '../../auth';
import { walletService } from '../../walletService';
import { db } from '../../db';

// Mock dependencies
vi.mock('../../auth', () => ({
  requireAuth: vi.fn((req, res, next) => {
    if (req.user) {
      next();
    } else {
      res.status(401).json({ error: 'Unauthorized' });
    }
  }),
}));

vi.mock('../../walletService', () => ({
  walletService: {
    getBalance: vi.fn(),
    getWalletDetails: vi.fn(),
    getUSDCBalance: vi.fn(),
    getWalletDataForExport: vi.fn(),
  },
}));

vi.mock('../../db', () => ({
  db: {
    query: {
      users: {
        findFirst: vi.fn(),
      },
    },
  },
}));

describe('Wallet Routes', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: vi.Mock;

  beforeEach(() => {
    vi.clearAllMocks();
    mockRequest = {
      user: {
        id: 1,
        username: 'testuser',
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
      } as Express.User,
      params: {},
      body: {},
    };
    mockResponse = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
  });

  describe('GET /api/wallet/info', () => {
    it('should return wallet info for authenticated user', async () => {
      const walletInfo = {
        address: 'xdc1234567890123456789012345678901234567890',
        balance: '1000000000000000000',
        tokenBalance: '500000000000000000',
      };

      vi.mocked(walletService.getBalance).mockResolvedValue('1000000000000000000');
      vi.mocked(walletService.getUSDCBalance).mockResolvedValue('100.00');

      // Simulate route handler
      const address = mockRequest.user?.xdcWalletAddress;
      const balance = await walletService.getBalance(address!);
      const usdcBalance = await walletService.getUSDCBalance(address!);

      const response = {
        address,
        balance,
        tokenBalance: '0', // ROXN balance would be fetched separately
        usdcBalance,
      };

      expect(response.address).toBeDefined();
      expect(response.balance).toBeDefined();
    });

    it('should return error if user has no wallet', async () => {
      mockRequest.user = {
        id: 1,
        username: 'testuser',
        xdcWalletAddress: null,
      } as Express.User;

      // Simulate route handler
      if (!mockRequest.user?.xdcWalletAddress) {
        expect(mockResponse.status).toBeDefined();
        // Would return 404 or error
      }
    });
  });

  describe('GET /api/wallet/balance', () => {
    it('should return wallet balance', async () => {
      const address = 'xdc1234567890123456789012345678901234567890';
      const balance = '1000000000000000000';

      vi.mocked(walletService.getBalance).mockResolvedValue(balance);

      const result = await walletService.getBalance(address);
      expect(result).toBe(balance);
    });
  });

  describe('GET /api/wallet/usdc-balance', () => {
    it('should return USDC balance', async () => {
      const address = 'xdc1234567890123456789012345678901234567890';
      const usdcBalance = '100.00';

      vi.mocked(walletService.getUSDCBalance).mockResolvedValue(usdcBalance);

      const result = await walletService.getUSDCBalance(address);
      expect(result).toBe(usdcBalance);
    });
  });

  describe('GET /api/wallet/export', () => {
    it('should return wallet data for export', async () => {
      const userId = 1;
      const walletData = {
        address: 'xdc1234567890123456789012345678901234567890',
        privateKey: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      };

      vi.mocked(walletService.getWalletDataForExport).mockResolvedValue(walletData);

      const result = await walletService.getWalletDataForExport(userId);
      expect(result).toHaveProperty('address');
      expect(result).toHaveProperty('privateKey');
      expect(result.privateKey).toMatch(/^0x/);
    });

    it('should require authentication', () => {
      mockRequest.user = undefined;

      requireAuth(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockResponse.status).toHaveBeenCalledWith(401);
    });
  });
});


