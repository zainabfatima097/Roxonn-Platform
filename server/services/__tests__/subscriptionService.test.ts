import { describe, it, expect, beforeEach, vi } from 'vitest';
import { subscriptionService } from '../../subscriptionService';
import { db } from '../../db';
import { subscriptions, subscriptionEvents } from '../../../shared/schema';

// Mock the database
vi.mock('../../db', () => ({
  db: {
    query: {
      subscriptions: {
        findFirst: vi.fn(),
      },
    },
    insert: vi.fn(),
    update: vi.fn(),
  },
}));

describe('SubscriptionService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createSubscription', () => {
    it('should create a new subscription', async () => {
      const subscriptionData = {
        userId: 1,
        plan: 'courses_yearly' as const,
        status: 'active' as const,
        provider: 'onramp' as const,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      };

      const createdSubscription = {
        id: 1,
        ...subscriptionData,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnValue({
          returning: vi.fn().mockResolvedValue([createdSubscription]),
        }),
      });

      (db.insert as any).mockImplementation((table) => {
        if (table === subscriptionEvents) {
          return {
            values: vi.fn().mockResolvedValue([]),
          };
        }
        return {
          values: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([createdSubscription]),
          }),
        };
      });

      const result = await subscriptionService.createSubscription(subscriptionData);
      expect(result.id).toBe(1);
      expect(result.userId).toBe(subscriptionData.userId);
      expect(result.plan).toBe(subscriptionData.plan);
    });
  });

  describe('activateOrRenewSubscription', () => {
    it('should create new subscription if none exists', async () => {
      const userId = 1;
      const plan = 'courses_yearly' as const;

      (db.query.subscriptions.findFirst as any).mockResolvedValue(null);

      const newSubscription = {
        id: 1,
        userId,
        plan,
        status: 'active' as const,
        provider: 'onramp' as const,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnValue({
          returning: vi.fn().mockResolvedValue([newSubscription]),
        }),
      });

      // Mock event logging
      (db.insert as any).mockImplementation((table) => {
        if (table === subscriptionEvents) {
          return {
            values: vi.fn().mockResolvedValue([]),
          };
        }
        return {
          values: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([newSubscription]),
          }),
        };
      });

      const result = await subscriptionService.activateOrRenewSubscription(userId, plan);
      expect(result.id).toBe(1);
      expect(result.status).toBe('active');
    });

    it('should renew existing subscription', async () => {
      const userId = 1;
      const plan = 'courses_yearly' as const;

      const existingSubscription = {
        id: 1,
        userId,
        plan,
        status: 'expired' as const,
        provider: 'onramp' as const,
        currentPeriodStart: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000),
        currentPeriodEnd: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000),
      };

      (db.query.subscriptions.findFirst as any).mockResolvedValue(existingSubscription);

      const renewedSubscription = {
        ...existingSubscription,
        status: 'active' as const,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      };

      (db.update as any).mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([renewedSubscription]),
          }),
        }),
      });

      // Mock event logging
      (db.insert as any).mockReturnValue({
        values: vi.fn().mockResolvedValue([]),
      });

      const result = await subscriptionService.activateOrRenewSubscription(userId, plan);
      expect(result.id).toBe(1);
      expect(result.status).toBe('active');
    });
  });

  describe('getSubscriptionStatus', () => {
    it('should return active status for valid subscription', async () => {
      const userId = 1;
      const futureDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

      (db.query.subscriptions.findFirst as any).mockResolvedValue({
        id: 1,
        userId,
        status: 'active',
        currentPeriodEnd: futureDate,
      });

      const status = await subscriptionService.getSubscriptionStatus(userId);
      expect(status.active).toBe(true);
      expect(status.subscription).toBeDefined();
    });

    it('should return inactive status when no subscription exists', async () => {
      const userId = 1;

      (db.query.subscriptions.findFirst as any).mockResolvedValue(null);

      const status = await subscriptionService.getSubscriptionStatus(userId);
      expect(status.active).toBe(false);
      expect(status.subscription).toBeUndefined();
    });

    it('should auto-expire expired subscriptions', async () => {
      const userId = 1;
      const pastDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);

      (db.query.subscriptions.findFirst as any).mockResolvedValue({
        id: 1,
        userId,
        status: 'active',
        currentPeriodEnd: pastDate,
      });

      (db.update as any).mockReturnValue({
        set: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
      });

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockResolvedValue([]),
      });

      const status = await subscriptionService.getSubscriptionStatus(userId);
      expect(status.active).toBe(false);
    });
  });

  describe('cancelSubscription', () => {
    it('should cancel a subscription', async () => {
      const subscriptionId = 1;

      (db.update as any).mockReturnValue({
        set: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
      });

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockResolvedValue([]),
      });

      await subscriptionService.cancelSubscription(subscriptionId);
      expect(db.update).toHaveBeenCalled();
    });
  });
});


