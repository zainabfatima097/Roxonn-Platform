import express, { type Express } from 'express';
import { registerRoutes } from '../routes';
import { setupAuth } from '../auth';
import cookieParser from 'cookie-parser';

/**
 * Create a test Express app for supertest integration tests
 * This allows us to test actual HTTP endpoints with middleware
 */
export async function createTestApp(): Promise<Express> {
  const app = express();
  
  // Basic middleware needed for tests
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  
  // Setup auth (will be mocked in tests)
  setupAuth(app);
  
  // Register routes (registerRoutes is async)
  await registerRoutes(app);
  
  return app;
}

