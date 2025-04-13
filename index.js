import express from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { z } from 'zod';
import morgan from 'morgan';
import fs from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

// Configuration initiale
dotenv.config();
const app = express();
const prisma = new PrismaClient();
const SYSTEM_WALLET_ID = '00000000-0000-0000-0000-000000000000'; // UUID du wallet système

// Constantes
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-please-change';
const TRANSACTION_FEE = 0.01; // 1%
const MIN_BALANCE = 0;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 100;

// Middlewares
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  message: 'Too many requests, please try again later.',
});
app.use(limiter);

// Logging
app.use(morgan('combined', {
  stream: fs.createWriteStream(new URL('./access.log', import.meta.url))
}));

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Swagger documentation
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'KivuCoin API',
      version: '1.0.0',
      description: 'API for KivuCoin cryptocurrency management',
    },
    servers: [
      {
        url: 'http://localhost:4000',
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        }
      }
    },
    security: [{
      bearerAuth: []
    }]
  },
  apis: ['./src/*.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Schémas de validation
const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

const transferSchema = z.object({
  toUserId: z.string().uuid(),
  amount: z.number().positive().max(1000000),
});

const emissionSchema = z.object({
  toUserId: z.string().uuid(),
  amount: z.number().positive(),
  reason: z.string().min(3),
});

// Middleware d'authentification
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Middleware de vérification admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Forbidden - Admin access required' });
  }
  next();
};

// Wrapper pour les handlers async
const asyncHandler = (fn) => (req, res, next) => 
  Promise.resolve(fn(req, res, next)).catch(next);

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       200:
 *         description: User created successfully
 *       400:
 *         description: Validation error or user already exists
 */
app.post('/auth/register', asyncHandler(async (req, res) => {
  const { email, password } = registerSchema.parse(req.body);
  const hashed = await bcrypt.hash(password, 10);
  
  const user = await prisma.user.create({
    data: { 
      email, 
      password: hashed, 
      role: 'USER', 
      wallet: { create: { balance: 0 } } 
    },
  });
  
  res.json({ message: 'User created successfully' });
}));

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid credentials
 */
app.post('/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = loginSchema.parse(req.body);
  const user = await prisma.user.findUnique({ 
    where: { email }, 
    include: { wallet: true } 
  });
  
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Enregistrer l'historique de connexion
  await prisma.loginHistory.create({
    data: {
      userId: user.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    }
  });
  
  const token = jwt.sign(
    { id: user.id, role: user.role, email: user.email }, 
    JWT_SECRET, 
    { expiresIn: '24h' }
  );
  
  res.json({ token });
}));

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Reset link sent
 *       404:
 *         description: User not found
 */
app.post('/auth/forgot-password', asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      token,
      expiresAt: new Date(Date.now() + 3600000) // 1 heure
    }
  });
  
  // En production, vous enverriez un email ici
  console.log(`Password reset token for ${email}: ${token}`);
  
  res.json({ message: 'Reset link sent' });
}));

/**
 * @swagger
 * /wallet/me:
 *   get:
 *     summary: Get current user's wallet
 *     tags: [Wallet]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Wallet details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Wallet'
 *       401:
 *         description: Unauthorized
 */
app.get('/wallet/me', auth, asyncHandler(async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    include: { wallet: true },
  });
  
  if (!user.wallet) {
    return res.status(404).json({ error: 'Wallet not found' });
  }
  
  res.json(user.wallet);
}));

/**
 * @swagger
 * /wallet/transfer:
 *   post:
 *     summary: Transfer KVC to another user
 *     tags: [Wallet]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - toUserId
 *               - amount
 *             properties:
 *               toUserId:
 *                 type: string
 *                 format: uuid
 *               amount:
 *                 type: number
 *                 minimum: 0.01
 *     responses:
 *       200:
 *         description: Transfer successful
 *       400:
 *         description: Invalid transfer
 *       401:
 *         description: Unauthorized
 */
app.post('/wallet/transfer', auth, asyncHandler(async (req, res) => {
  const { toUserId, amount } = transferSchema.parse(req.body);
  const fee = amount * TRANSACTION_FEE;
  const total = amount + fee;
  
  const fromWallet = await prisma.wallet.findUnique({ 
    where: { userId: req.user.id } 
  });
  const toWallet = await prisma.wallet.findUnique({ 
    where: { userId: toUserId } 
  });
  
  if (!fromWallet || !toWallet) {
    return res.status(404).json({ error: 'Wallet not found' });
  }
  
  if (fromWallet.balance < total) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }
  
  if (fromWallet.userId === toWallet.userId) {
    return res.status(400).json({ error: 'Cannot transfer to yourself' });
  }
  
  await prisma.$transaction([
    // Débit du compte émetteur
    prisma.wallet.update({ 
      where: { id: fromWallet.id }, 
      data: { balance: { decrement: total } } 
    }),
    // Crédit du compte destinataire
    prisma.wallet.update({ 
      where: { id: toWallet.id }, 
      data: { balance: { increment: amount } } 
    }),
    // Transaction principale
    prisma.transaction.create({
      data: {
        fromWalletId: fromWallet.id,
        toWalletId: toWallet.id,
        amount,
        fee,
        type: 'TRANSFER',
        reason: 'user transfer',
      },
    }),
    // Frais de transaction
    prisma.transaction.create({
      data: {
        fromWalletId: fromWallet.id,
        toWalletId: SYSTEM_WALLET_ID,
        amount: fee,
        type: 'FEE',
        reason: 'transfer fee',
      },
    }),
  ]);
  
  // Créer des notifications
  await prisma.notification.createMany({
    data: [
      {
        userId: req.user.id,
        message: `You sent ${amount} KVC to ${toWallet.userId}`,
        type: 'TRANSFER_OUT'
      },
      {
        userId: toUserId,
        message: `You received ${amount} KVC from ${req.user.id}`,
        type: 'TRANSFER_IN'
      }
    ]
  });
  
  res.json({ 
    message: 'Transfer complete', 
    amount, 
    fee,
    newBalance: fromWallet.balance - total
  });
}));

/**
 * @swagger
 * /transactions/me:
 *   get:
 *     summary: Get current user's transactions
 *     tags: [Transactions]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of transactions
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Transaction'
 *       401:
 *         description: Unauthorized
 */
app.get('/transactions/me', auth, asyncHandler(async (req, res) => {
  const transactions = await prisma.transaction.findMany({
    where: {
      OR: [
        { fromWallet: { userId: req.user.id } },
        { toWallet: { userId: req.user.id } },
      ],
    },
    include: { 
      fromWallet: { select: { userId: true } },
      toWallet: { select: { userId: true } }
    },
    orderBy: { createdAt: 'desc' },
    take: 50,
  });
  
  res.json(transactions);
}));

/**
 * @swagger
 * /notifications:
 *   get:
 *     summary: Get current user's notifications
 *     tags: [Notifications]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of notifications
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Notification'
 *       401:
 *         description: Unauthorized
 */
app.get('/notifications', auth, asyncHandler(async (req, res) => {
  const notifications = await prisma.notification.findMany({
    where: { userId: req.user.id },
    orderBy: { createdAt: 'desc' },
    take: 20,
  });
  
  res.json(notifications);
}));

/**
 * @swagger
 * /admin/emit:
 *   post:
 *     summary: Emit new KVC (admin only)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - toUserId
 *               - amount
 *               - reason
 *             properties:
 *               toUserId:
 *                 type: string
 *                 format: uuid
 *               amount:
 *                 type: number
 *                 minimum: 0.01
 *               reason:
 *                 type: string
 *                 minLength: 3
 *     responses:
 *       200:
 *         description: KVC emitted successfully
 *       403:
 *         description: Forbidden (admin access required)
 *       404:
 *         description: User not found
 */
app.post('/admin/emit', auth, isAdmin, asyncHandler(async (req, res) => {
  const { toUserId, amount, reason } = emissionSchema.parse(req.body);
  const wallet = await prisma.wallet.findUnique({ where: { userId: toUserId } });
  
  if (!wallet) {
    return res.status(404).json({ error: 'User wallet not found' });
  }
  
  await prisma.$transaction([
    prisma.wallet.update({ 
      where: { id: wallet.id }, 
      data: { balance: { increment: amount } } 
    }),
    prisma.transaction.create({
      data: {
        toWalletId: wallet.id,
        amount,
        type: 'EMISSION',
        reason,
      },
    }),
    prisma.emission.create({
      data: {
        toWalletId: wallet.id,
        amount,
        reason,
        adminId: req.user.id,
      },
    }),
    prisma.notification.create({
      data: {
        userId: toUserId,
        message: `You received ${amount} KVC from system: ${reason}`,
        type: 'SYSTEM_CREDIT'
      }
    })
  ]);
  
  res.json({ message: 'KVC emitted successfully' });
}));

/**
 * @swagger
 * /admin/emissions:
 *   get:
 *     summary: Get all emissions (admin only)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of emissions
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Emission'
 *       403:
 *         description: Forbidden (admin access required)
 */
app.get('/admin/emissions', auth, isAdmin, asyncHandler(async (req, res) => {
  const emissions = await prisma.emission.findMany({ 
    include: { 
      toWallet: { select: { userId: true } },
      admin: { select: { email: true } }
    },
    orderBy: { createdAt: 'desc' }
  });
  
  res.json(emissions);
}));

/**
 * @swagger
 * /admin/transactions:
 *   get:
 *     summary: Get all transactions (admin only)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of transactions
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Transaction'
 *       403:
 *         description: Forbidden (admin access required)
 */
app.get('/admin/transactions', auth, isAdmin, asyncHandler(async (req, res) => {
  const transactions = await prisma.transaction.findMany({ 
    include: { 
      toWallet: { select: { userId: true } },
      fromWallet: { select: { userId: true } }
    },
    orderBy: { createdAt: 'desc' },
    take: 100,
  });
  
  res.json(transactions);
}));

// Middleware de gestion d'erreurs
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err instanceof z.ZodError) {
    return res.status(400).json({
      error: 'Validation error',
      details: err.errors
    });
  }
  
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Démarrer le serveur
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`KivuCoin backend running on http://localhost:${PORT}`);
  console.log(`API documentation available at http://localhost:${PORT}/api-docs`);
});

// Vérifier la connexion à la base de données au démarrage
prisma.$connect()
  .then(() => console.log('Connected to database'))
  .catch(err => {
    console.error('Database connection error', err);
    process.exit(1);
  });