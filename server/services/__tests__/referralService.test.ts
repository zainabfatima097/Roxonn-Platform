import { describe, it, expect, beforeEach, vi } from 'vitest';
import { referralService } from '../referralService';
import { db } from '../../db';
import { referralCodes, referrals, referralRewards, users } from '../../../shared/schema';

// Mock the database
vi.mock('../../db', () => ({
  db: {
    query: {
      referralCodes: {
        findFirst: vi.fn(),
      },
      referrals: {
        findFirst: vi.fn(),
        findMany: vi.fn(),
      },
      users: {
        findFirst: vi.fn(),
      },
    },
    insert: vi.fn(),
    update: vi.fn(),
  },
}));

// Mock email service
vi.mock('../../email', () => ({
  sendPayoutRequestNotification: vi.fn(),
}));

describe('ReferralService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('generateReferralCode', () => {
    it('should return existing code if user already has one', async () => {
      const userId = 1;
      const existingCode = 'EXISTING123';

      (db.query.referralCodes.findFirst as any).mockResolvedValue({
        id: 1,
        userId,
        code: existingCode,
        isActive: true,
      });

      const code = await referralService.generateReferralCode(userId);
      expect(code).toBe(existingCode);
    });

    it('should generate unique referral code from username', async () => {
      const userId = 1;
      const username = 'testuser';

      (db.query.referralCodes.findFirst as any)
        .mockResolvedValueOnce(null) // No existing code
        .mockResolvedValueOnce(null); // Code is unique

      (db.query.users.findFirst as any).mockResolvedValue({
        id: userId,
        username,
      });

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnThis(),
      });

      const code = await referralService.generateReferralCode(userId);
      expect(code).toMatch(/^TESTUSER\d{4}$/);
    });

    it('should generate random code when username unavailable', async () => {
      const userId = 1;

      (db.query.referralCodes.findFirst as any)
        .mockResolvedValueOnce(null) // No existing code
        .mockResolvedValueOnce(null); // Code is unique

      (db.query.users.findFirst as any).mockResolvedValue({
        id: userId,
        username: null,
      });

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnThis(),
      });

      const code = await referralService.generateReferralCode(userId);
      expect(code).toMatch(/^ROXONN[A-Z0-9]+$/);
      expect(code.length).toBeGreaterThan(8);
    });
  });

  describe('applyReferralCode', () => {
    it('should create referral relationship for valid code', async () => {
      const newUserId = 2;
      const code = 'VALID123';
      const referrerId = 1;

      (db.query.referralCodes.findFirst as any).mockResolvedValue({
        id: 1,
        userId: referrerId,
        code: code.toUpperCase(),
        isActive: true,
      });

      (db.query.referrals.findFirst as any).mockResolvedValue(null); // No existing referral

      (db.query.users.findFirst as any).mockResolvedValue({
        id: referrerId,
        username: 'referrer',
      });

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnThis(),
      });

      (db.update as any).mockReturnValue({
        set: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
      });

      const result = await referralService.applyReferralCode(newUserId, code);
      expect(result.success).toBe(true);
      expect(result.referrerUsername).toBeDefined();
    });

    it('should reject invalid referral codes', async () => {
      const newUserId = 2;
      const code = 'INVALID123';

      (db.query.referralCodes.findFirst as any).mockResolvedValue(null);

      const result = await referralService.applyReferralCode(newUserId, code);
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid or inactive referral code');
    });

    it('should reject self-referral', async () => {
      const userId = 1;
      const code = 'MYCODE123';

      (db.query.referralCodes.findFirst as any).mockResolvedValue({
        id: 1,
        userId,
        code: code.toUpperCase(),
        isActive: true,
      });

      const result = await referralService.applyReferralCode(userId, code);
      expect(result.success).toBe(false);
      expect(result.error).toBe('You cannot use your own referral code');
    });

    it('should reject if user was already referred', async () => {
      const newUserId = 2;
      const code = 'VALID123';

      (db.query.referralCodes.findFirst as any).mockResolvedValue({
        id: 1,
        userId: 1,
        code: code.toUpperCase(),
        isActive: true,
      });

      (db.query.referrals.findFirst as any).mockResolvedValue({
        id: 1,
        referredId: newUserId,
      });

      const result = await referralService.applyReferralCode(newUserId, code);
      expect(result.success).toBe(false);
      expect(result.error).toBe('You have already been referred');
    });
  });

  describe('getReferralStats', () => {
    it('should calculate correct referral statistics', async () => {
      const userId = 1;

      (db.query.referrals.findMany as any).mockResolvedValue([
        { status: 'pending', usdcReward: null, roxnReward: null },
        { status: 'converted', usdcReward: '2.0', roxnReward: '10.0' },
        { status: 'rewarded', usdcReward: '2.0', roxnReward: '10.0' },
        { status: 'rewarded', usdcReward: '1.5', roxnReward: '10.0' },
      ]);

      const stats = await referralService.getReferralStats(userId);
      expect(stats.totalReferrals).toBe(4);
      expect(stats.pendingReferrals).toBe(1);
      expect(stats.convertedReferrals).toBe(3);
      expect(parseFloat(stats.totalUsdcEarned)).toBe(3.5);
      expect(parseFloat(stats.totalRoxnEarned)).toBe(20.0);
    });
  });

  describe('validateCode', () => {
    it('should return true for valid active code', async () => {
      const code = 'VALID123';

      (db.query.referralCodes.findFirst as any).mockResolvedValue({
        id: 1,
        code: code.toUpperCase(),
        isActive: true,
      });

      const isValid = await referralService.validateCode(code);
      expect(isValid).toBe(true);
    });

    it('should return false for invalid code', async () => {
      const code = 'INVALID123';

      (db.query.referralCodes.findFirst as any).mockResolvedValue(null);

      const isValid = await referralService.validateCode(code);
      expect(isValid).toBe(false);
    });
  });
});


