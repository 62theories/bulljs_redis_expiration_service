import express from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import ms from 'ms';
import { add } from 'date-fns';
import Queue from 'bull';

// Add this near the top of your file, after the imports
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

const ACCESS_TOKEN_EXPIRY = '5m';
const REFRESH_TOKEN_EXPIRY = '7d';
const REFRESH_TOKEN_EXPIRY_MS = ms(REFRESH_TOKEN_EXPIRY);

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Use an environment variable in production

// Initialize Prisma client
const prisma = new PrismaClient();
app.use(express.json());

// Initialize Bull queue for refresh tokens
const refreshTokenQueue = new Queue('refreshTokens', process.env.REDIS_URL || 'redis://localhost:6379');

// Middleware to connect to the database before each request
app.use(async (req: express.Request, res: express.Response, next) => {
  try {
    await prisma.$connect();
    next();
  } catch (error) {
    console.error('Failed to connect to the database', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/', (req: express.Request, res: express.Response) => {
  res.send('Hello, TypeScript with Express and Prisma!');
});

// Example route using Prisma
app.get('/users', async (req: express.Request, res: express.Response) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    console.error('Error fetching users', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Register API endpoint
app.post('/register', async (req: express.Request, res: express.Response) => {
  try {
    const { username, password } = req.body;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      res.status(400).json({ error: 'Username already exists' });
      return
    }
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
      },
    });

    res.status(201).json({ message: 'User registered successfully', userId: newUser.id });
  } catch (error) {
    console.error('Error registering user', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Login API endpoint
app.post('/login', async (req: express.Request, res: express.Response) => {
  try {
    const { username, password } = req.body as { username: string; password: string };

    // Find the user
    const user = await prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
       res.status(401).json({ error: 'Invalid credentials' });
       return
    }

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Save refresh token to Redis using Bull queue
    await refreshTokenQueue.add(
      refreshToken,
      { userId: user.id },
      { removeOnComplete: true, removeOnFail: true, delay: REFRESH_TOKEN_EXPIRY_MS }
    );

    res.json({ message: 'Login successful', accessToken, refreshToken });
  } catch (error) {
    console.error('Error logging in', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Add refresh token endpoint
app.post('/refresh-token', async (req: express.Request, res: express.Response) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    res.status(400).json({ error: 'Refresh token is required' });
    return;
  }

  try {
    const job = await refreshTokenQueue.getJob(refreshToken);

    if (!job) {
      res.status(403).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    const { userId } = job.data;
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      res.status(403).json({ error: 'User not found' });
      return;
    }

    const accessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    // Remove old refresh token and add new one
    await job.remove();
    await refreshTokenQueue.add(
      newRefreshToken,
      { userId: user.id },
      { removeOnComplete: true, removeOnFail: true, delay: REFRESH_TOKEN_EXPIRY_MS }
    );

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error('Error refreshing token', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Helper functions for token generation
function generateAccessToken(user: any): string {
  return jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

function generateRefreshToken(user: any): string {
  return uuidv4();
}

// Middleware to verify JWT
const authenticateToken: express.RequestHandler = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    res.sendStatus(401);
    return;
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      res.sendStatus(403);
      return;
    }
    req.user = user;
    next();
  });
};

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

// Gracefully shut down the Prisma client and Bull queue when the app is terminated
process.on('SIGINT', async () => {
  await prisma.$disconnect();
  await refreshTokenQueue.close();
  process.exit();
});
