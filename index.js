import express from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

const app = express();
const prisma = new PrismaClient();


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requêtes
  message: 'Trop de requêtes. Réessaie plus tard.',
});

app.use(limiter);
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'kivucoin-2025'; // Change pour prod

// Auth middleware
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Forbidden' });
  next();
};

// Register
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: { email, password: hashed, role: 'USER', wallet: { create: {} } },
    });
    res.json({ message: 'User created' });
  } catch (err) {
    res.status(400).json({ error: 'User exists' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email }, include: { wallet: true } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
  res.json({ token });
});

// Get wallet
app.get('/wallet/me', auth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    include: { wallet: true },
  });
  res.json(user.wallet);
});

// Transfer KVC
app.post('/wallet/transfer', auth, async (req, res) => {
  const { toUserId, amount } = req.body;
  const from = await prisma.wallet.findUnique({ where: { userId: req.user.id } });
  const to = await prisma.wallet.findUnique({ where: { userId: toUserId } });
  if (!from || !to || from.balance < amount) return res.status(400).json({ error: 'Invalid transfer' });
  await prisma.$transaction([
    prisma.wallet.update({ where: { id: from.id }, data: { balance: { decrement: amount } } }),
    prisma.wallet.update({ where: { id: to.id }, data: { balance: { increment: amount } } }),
    prisma.transaction.create({
      data: {
        fromWalletId: from.id,
        toWalletId: to.id,
        amount,
        type: 'TRANSFER',
        reason: 'user transfer',
      },
    }),
  ]);
  res.json({ message: 'Transfer complete' });
});

app.get('/transactions/me', auth, async (req, res) => {
    const tx = await prisma.transaction.findMany({
      where: {
        OR: [
          { fromWallet: { userId: req.user.id } },
          { toWallet: { userId: req.user.id } },
        ],
      },
      include: { fromWallet: true, toWallet: true },
      orderBy: { createdAt: 'desc' },
    });
    res.json(tx);
  });
  

// Emit KVC (admin only)
app.post('/admin/emit', auth, isAdmin, async (req, res) => {
  const { toUserId, amount, reason } = req.body;
  const wallet = await prisma.wallet.findUnique({ where: { userId: toUserId } });
  if (!wallet) return res.status(404).json({ error: 'User not found' });
  await prisma.$transaction([
    prisma.wallet.update({ where: { id: wallet.id }, data: { balance: { increment: amount } } }),
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
      },
    }),
  ]);
  res.json({ message: 'KVC emitted' });
});

// Admin - Get emissions
app.get('/admin/emissions', auth, isAdmin, async (req, res) => {
  const emissions = await prisma.emission.findMany({ include: { toWallet: true } });
  res.json(emissions);
});

// Admin - Get transactions
app.get('/admin/transactions', auth, isAdmin, async (req, res) => {
  const tx = await prisma.transaction.findMany({ include: { toWallet: true, fromWallet: true } });
  res.json(tx);
});

app.listen(4000, () => console.log('KivuCoin backend running on http://localhost:4000'));
