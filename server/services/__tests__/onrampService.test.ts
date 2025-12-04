import { describe, it, expect, beforeEach, vi } from 'vitest';
import { onrampService } from '../../onrampService';
import { db } from '../../db';
import { TransactionStatus } from '../../../shared/schema';

// Mock the database
vi.mock('../../db', () => ({
  db: {
    query: {
      onrampTransactions: {
        findFirst: vi.fn(),
        findMany: vi.fn(),
      },
    },
    insert: vi.fn(),
    update: vi.fn(),
  },
}));

describe('OnrampService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createTransaction', () => {
    it('should create a new transaction', async () => {
      const transactionData = {
        userId: 1,
        merchantRecognitionId: 'test-merchant-id-123',
        status: TransactionStatus.INITIATED,
        amount: '100.00',
        currency: 'USDC',
      };

      const createdTransaction = {
        id: 1,
        ...transactionData,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnValue({
          returning: vi.fn().mockResolvedValue([createdTransaction]),
        }),
      });

      const result = await onrampService.createTransaction(transactionData);
      expect(result).not.toBeNull();
      expect(result?.merchantRecognitionId).toBe(transactionData.merchantRecognitionId);
      expect(result?.status).toBe(TransactionStatus.INITIATED);
    });

    it('should return null on error', async () => {
      const transactionData = {
        userId: 1,
        merchantRecognitionId: 'test-merchant-id-123',
        status: TransactionStatus.INITIATED,
        amount: '100.00',
        currency: 'USDC',
      };

      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnValue({
          returning: vi.fn().mockRejectedValue(new Error('Database error')),
        }),
      });

      const result = await onrampService.createTransaction(transactionData);
      expect(result).toBeNull();
    });
  });

  describe('updateTransaction', () => {
    it('should update an existing transaction', async () => {
      const merchantRecognitionId = 'test-merchant-id-123';
      const updates = {
        status: TransactionStatus.SUCCESS,
        amount: '100.00',
      };

      const updatedTransaction = {
        id: 1,
        userId: 1,
        merchantRecognitionId,
        status: TransactionStatus.SUCCESS,
        amount: '100.00',
        currency: 'USDC',
        updatedAt: new Date(),
      };

      (db.update as any).mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([updatedTransaction]),
          }),
        }),
      });

      const result = await onrampService.updateTransaction(merchantRecognitionId, updates);
      expect(result).not.toBeNull();
      expect(result?.status).toBe(TransactionStatus.SUCCESS);
    });

    it('should return null if transaction not found', async () => {
      const merchantRecognitionId = 'non-existent-id';
      const updates = { status: TransactionStatus.SUCCESS };

      (db.update as any).mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([]),
          }),
        }),
      });

      const result = await onrampService.updateTransaction(merchantRecognitionId, updates);
      expect(result).toBeNull();
    });
  });

  describe('getTransactionByMerchantId', () => {
    it('should return transaction for valid merchant ID', async () => {
      const merchantRecognitionId = 'test-merchant-id-123';
      const transaction = {
        id: 1,
        userId: 1,
        merchantRecognitionId,
        status: TransactionStatus.SUCCESS,
        amount: '100.00',
        currency: 'USDC',
        createdAt: new Date(),
      };

      (db.query.onrampTransactions.findFirst as any).mockResolvedValue(transaction);

      const result = await onrampService.getTransactionByMerchantId(merchantRecognitionId);
      expect(result).not.toBeNull();
      expect(result?.merchantRecognitionId).toBe(merchantRecognitionId);
    });

    it('should return null for non-existent transaction', async () => {
      const merchantRecognitionId = 'non-existent-id';

      (db.query.onrampTransactions.findFirst as any).mockResolvedValue(null);

      const result = await onrampService.getTransactionByMerchantId(merchantRecognitionId);
      expect(result).toBeNull();
    });
  });

  describe('getUserTransactions', () => {
    it('should return user transactions', async () => {
      const userId = 1;
      const transactions = [
        {
          id: 1,
          userId,
          merchantRecognitionId: 'merchant-1',
          status: TransactionStatus.SUCCESS,
          amount: '100.00',
          createdAt: new Date(),
        },
        {
          id: 2,
          userId,
          merchantRecognitionId: 'merchant-2',
          status: TransactionStatus.PENDING,
          amount: '50.00',
          createdAt: new Date(),
        },
      ];

      (db.query.onrampTransactions.findMany as any).mockResolvedValue(transactions);

      const result = await onrampService.getUserTransactions(userId);
      expect(result).toHaveLength(2);
      expect(result[0].userId).toBe(userId);
    });

    it('should return empty array on error', async () => {
      const userId = 1;

      (db.query.onrampTransactions.findMany as any).mockRejectedValue(new Error('Database error'));

      const result = await onrampService.getUserTransactions(userId);
      expect(result).toEqual([]);
    });
  });

  describe('mapStatus', () => {
    it('should map success status correctly', () => {
      expect(onrampService.mapStatus('success', undefined)).toBe(TransactionStatus.SUCCESS);
      expect(onrampService.mapStatus(undefined, 'SUCCESS')).toBe(TransactionStatus.SUCCESS);
    });

    it('should map failed status correctly', () => {
      expect(onrampService.mapStatus('failed', undefined)).toBe(TransactionStatus.FAILED);
      expect(onrampService.mapStatus(undefined, 'FAILED')).toBe(TransactionStatus.FAILED);
    });

    it('should map processing status correctly', () => {
      expect(onrampService.mapStatus('processing', undefined)).toBe(TransactionStatus.PROCESSING);
      expect(onrampService.mapStatus(undefined, 'PROCESSING')).toBe(TransactionStatus.PROCESSING);
    });

    it('should default to INITIATED for unknown status', () => {
      expect(onrampService.mapStatus('unknown', undefined)).toBe(TransactionStatus.INITIATED);
      expect(onrampService.mapStatus(undefined, undefined)).toBe(TransactionStatus.INITIATED);
    });
  });
});


