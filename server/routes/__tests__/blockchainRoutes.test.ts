import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../__tests__/test-app';
import type { Express, Request, Response, NextFunction } from 'express';
import { blockchain } from '../../blockchain';
import { requireAuth } from '../../auth';
import type { Mock } from 'vitest';

// Mock dependencies
vi.mock('../../blockchain', () => ({
  blockchain: {
    getRepository: vi.fn(),
    allocateIssueReward: vi.fn(),
    addXDCFundToRepository: vi.fn(),
    addROXNFundToRepository: vi.fn(),
    addUSDCFundToRepository: vi.fn(),
    registerUser: vi.fn(),
  },
}));

vi.mock('../../auth', () => ({
  requireAuth: vi.fn((req: Request, res: Response, next: NextFunction) => {
    // Default: allow through (tests will override as needed)
    next();
  }),
  csrfProtection: vi.fn((req: Request, res: Response, next: NextFunction) => next()),
}));

vi.mock('../../security/middlewares', () => ({
  securityMiddlewares: {
    repoRateLimiter: vi.fn((req: Request, res: Response, next: NextFunction) => next()),
    securityMonitor: vi.fn((req: Request, res: Response, next: NextFunction) => next()),
  },
}));

describe('Blockchain Routes', () => {
  let app: Express;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await createTestApp();
  });

  describe('GET /api/blockchain/repository/:repoId', () => {
    it('should return repository details', async () => {
      const repoId = 1;
      const repoDetails = {
        xdcPoolRewards: '100.0',
        roxnPoolRewards: '50.0',
        usdcPoolRewards: '200.0',
        poolManagers: ['xdc1234567890123456789012345678901234567890'],
        contributors: [],
        issues: [],
      };

      vi.mocked(blockchain.getRepository).mockResolvedValue(repoDetails);

      const response = await request(app)
        .get(`/api/blockchain/repository/${repoId}`)
        .expect(200);

      expect(response.body).toHaveProperty('xdcPoolRewards');
      expect(response.body).toHaveProperty('roxnPoolRewards');
      expect(response.body).toHaveProperty('usdcPoolRewards');
      expect(response.body.xdcPoolRewards).toBe('100.0');
      expect(blockchain.getRepository).toHaveBeenCalledWith(repoId);
    });

    it('should handle repository not found', async () => {
      const repoId = 999;

      vi.mocked(blockchain.getRepository).mockResolvedValue({
        xdcPoolRewards: '0.0',
        roxnPoolRewards: '0.0',
        usdcPoolRewards: '0.0',
        poolManagers: [],
        contributors: [],
        issues: [],
      });

      const response = await request(app)
        .get(`/api/blockchain/repository/${repoId}`)
        .expect(200);

      expect(response.body.xdcPoolRewards).toBe('0.0');
      expect(blockchain.getRepository).toHaveBeenCalledWith(repoId);
    });
  });

  describe('GET /api/blockchain/repository/:repoId/funding-status', () => {
    it('should return funding status for authenticated user', async () => {
      // Mock requireAuth to inject user
      vi.mocked(requireAuth).mockImplementation((req, res, next) => {
        req.user = {
          id: 1,
          username: 'testuser',
          role: 'poolmanager',
        } as Express.User;
        next();
        return undefined;
      });

      const response = await request(app)
        .get('/api/blockchain/repository/1/funding-status')
        .expect(200);

      expect(response.body).toHaveProperty('dailyLimit');
      expect(response.body).toHaveProperty('currentTotal');
      expect(response.body).toHaveProperty('remainingLimit');
    });

    it('should require authentication for funding status', async () => {
      // Mock requireAuth to reject
      vi.mocked(requireAuth).mockImplementation((req, res) => {
        res.status(401).json({ error: 'Unauthorized' });
        return res;
      });

      await request(app)
        .get('/api/blockchain/repository/1/funding-status')
        .expect(401);
    });
  });
});
