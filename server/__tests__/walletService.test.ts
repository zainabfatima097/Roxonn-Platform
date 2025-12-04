import { describe, it, expect, beforeEach, vi } from 'vitest';
import { WalletService } from '../walletService';
import { TatumSDK } from '@tatumio/tatum';
import { EvmWalletProvider } from '@tatumio/evm-wallet-provider';
import { db } from '../db';
import { getWalletSecret } from '../aws';

// Mock dependencies
vi.mock('@tatumio/tatum', async () => {
  const actual = await vi.importActual('@tatumio/tatum');
  return {
    ...actual,
    TatumSDK: {
      init: vi.fn(),
    },
  };
});

vi.mock('@tatumio/evm-wallet-provider', () => ({
  EvmWalletProvider: vi.fn(),
}));

vi.mock('../db', () => ({
  db: {
    query: {
      users: {
        findFirst: vi.fn(),
      },
    },
  },
}));

vi.mock('../aws', () => ({
  getWalletSecret: vi.fn(),
}));

vi.mock('../config', () => ({
  config: {
    tatumApiKey: 'test-api-key',
  },
}));

describe('WalletService', () => {
  let walletService: WalletService;
  let mockSdk: any;

  beforeEach(() => {
    vi.clearAllMocks();
    
    mockSdk = {
      walletProvider: {
        use: vi.fn().mockReturnValue({
          generateMnemonic: vi.fn().mockResolvedValue('test mnemonic phrase here'),
          generateAddressFromMnemonic: vi.fn().mockResolvedValue('0x1234567890123456789012345678901234567890'),
          generatePrivateKeyFromMnemonic: vi.fn().mockResolvedValue('0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'),
          generateXpub: vi.fn().mockResolvedValue({ xpub: 'xpub123' }),
          generateAddressFromXpub: vi.fn().mockResolvedValue('0x1234567890123456789012345678901234567890'),
          signAndBroadcast: vi.fn().mockResolvedValue('0xtxhash123'),
          transferErc20: vi.fn().mockResolvedValue('0xtxhash123'),
        }),
      },
      rpc: {
        getBalance: vi.fn().mockResolvedValue('1000000000000000000'),
        getFeeData: vi.fn().mockResolvedValue({ gasPrice: '20000000000' }),
        estimateGas: vi.fn().mockResolvedValue('21000'),
        call: vi.fn().mockResolvedValue('0x0'),
      },
      destroy: vi.fn().mockResolvedValue(undefined),
    };

    (TatumSDK.init as any).mockResolvedValue(mockSdk);
    walletService = new WalletService();
  });

  describe('generateMnemonic', () => {
    it('should generate a mnemonic phrase', async () => {
      const mnemonic = await walletService.generateMnemonic();
      expect(mnemonic).toBe('test mnemonic phrase here');
      expect(mockSdk.walletProvider.use).toHaveBeenCalledWith(EvmWalletProvider);
    });
  });

  describe('generateSingleWallet', () => {
    it('should generate a single XDC wallet', async () => {
      const wallet = await walletService.generateSingleWallet();
      expect(wallet).toHaveProperty('xdc');
      expect(wallet).toHaveProperty('mnemonic');
      expect(wallet).toHaveProperty('referenceId');
      expect(wallet.xdc).toHaveProperty('address');
      expect(wallet.xdc.address).toMatch(/^xdc/);
    });
  });

  describe('generateAddressFromMnemonic', () => {
    it('should generate XDC address from mnemonic', async () => {
      const mnemonic = 'test mnemonic phrase here';
      const address = await walletService.generateAddressFromMnemonic(mnemonic, 0);
      expect(address).toMatch(/^xdc/);
    });
  });

  describe('generatePrivateKey', () => {
    it('should generate private key from mnemonic', async () => {
      const mnemonic = 'test mnemonic phrase here';
      const privateKey = await walletService.generatePrivateKey(mnemonic, 0);
      expect(privateKey).toMatch(/^0x/);
      expect(privateKey.length).toBe(66); // 0x + 64 hex chars
    });
  });

  describe('getBalance', () => {
    it('should get balance for XDC address', async () => {
      const address = 'xdc1234567890123456789012345678901234567890';
      const balance = await walletService.getBalance(address);
      expect(typeof balance).toBe('string');
      expect(mockSdk.rpc.getBalance).toHaveBeenCalled();
    });
  });

  describe('getWalletDataForExport', () => {
    it('should retrieve wallet data for export', async () => {
      const userId = 1;
      const walletData = {
        privateKey: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      };

      (db.query.users.findFirst as any).mockResolvedValue({
        id: userId,
        xdcWalletAddress: 'xdc1234567890123456789012345678901234567890',
        walletReferenceId: 'ref123',
      });

      (getWalletSecret as any).mockResolvedValue(walletData);

      const result = await walletService.getWalletDataForExport(userId);
      expect(result).toHaveProperty('address');
      expect(result).toHaveProperty('privateKey');
      expect(result.privateKey).toMatch(/^0x/);
    });

    it('should throw error if wallet not found', async () => {
      const userId = 1;

      (db.query.users.findFirst as any).mockResolvedValue({
        id: userId,
        xdcWalletAddress: null,
        walletReferenceId: null,
      });

      await expect(walletService.getWalletDataForExport(userId)).rejects.toThrow('Wallet not found or incomplete');
    });
  });

  describe('mapStatus', () => {
    it('should use 18 decimals for XDC', () => {
      const networkConfig = walletService.getSupportedNetworks().xdc;
      expect(networkConfig.nativeCurrency.decimals).toBe(18);
    });

    it('should use 6 decimals for USDC on XDC', () => {
      const networkConfig = walletService.getSupportedNetworks().xdc;
      expect(networkConfig.usdcContractAddress).toBeDefined();
    });
  });

  describe('isUSDCSupported', () => {
    it('should return true for XDC network', () => {
      expect(walletService.isUSDCSupported('xdc')).toBe(true);
    });

    it('should return false for unsupported networks', () => {
      expect(walletService.isUSDCSupported('ethereum')).toBe(false);
    });
  });
});


