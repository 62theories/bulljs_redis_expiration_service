import express from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import ms from "ms";
import { add } from "date-fns";
import Queue from "bull";
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import { Job } from "bull";

// Add this near the top of your file, after the imports
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

const ACCESS_TOKEN_EXPIRY = "5m";
const REFRESH_TOKEN_EXPIRY = "7d";
const REFRESH_TOKEN_EXPIRY_MS = ms(REFRESH_TOKEN_EXPIRY);

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key"; // Use an environment variable in production

// OpenAPI configuration
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Express API with JWT Authentication",
      version: "1.0.0",
      description: "A simple Express API with JWT authentication",
    },
    servers: [
      {
        url: `http://localhost:${port}`,
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: ["./src/index.ts"], // Path to the API docs
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Initialize Prisma client
const prisma = new PrismaClient();
app.use(express.json());

// Initialize Bull queue for refresh tokens
const refreshTokenQueue = new Queue(
  "refreshTokens",
  process.env.REDIS_URL || "redis://localhost:6379"
);

// Middleware to connect to the database before each request
app.use(async (req: express.Request, res: express.Response, next) => {
  try {
    await prisma.$connect();
    next();
  } catch (error) {
    console.error("Failed to connect to the database", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/", (req: express.Request, res: express.Response) => {
  res.send("Hello, TypeScript with Express and Prisma!");
});

// Example route using Prisma
app.get("/users", async (req: express.Request, res: express.Response) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    console.error("Error fetching users", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Register API endpoint
/**
 * @openapi
 * /register:
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
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Username already exists
 *       500:
 *         description: Internal Server Error
 */
app.post("/register", async (req: express.Request, res: express.Response) => {
  try {
    const { username, password } = req.body;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      res.status(400).json({ error: "Username already exists" });
      return;
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

    res
      .status(201)
      .json({ message: "User registered successfully", userId: newUser.id });
  } catch (error) {
    console.error("Error registering user", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Login API endpoint
/**
 * @openapi
 * /login:
 *   post:
 *     summary: Login a user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       500:
 *         description: Internal Server Error
 */
app.post("/login", async (req: express.Request, res: express.Response) => {
  try {
    const { username, password } = req.body as {
      username: string;
      password: string;
    };

    // Find the user
    const user = await prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Save refresh token to Redis using Bull queue
    await refreshTokenQueue.add(
      "refreshToken",
      {
        userId: user.id,
        refreshToken,
      },
      {
        jobId: refreshToken, // Use refreshToken as jobId for easy retrieval
        removeOnComplete: true,
        removeOnFail: true,
        delay: REFRESH_TOKEN_EXPIRY_MS, // Set the job to be processed after the token expires
      }
    );

    res.json({ message: "Login successful", accessToken, refreshToken });
  } catch (error) {
    console.error("Error logging in", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Add refresh token endpoint
/**
 * @openapi
 * /refresh-token:
 *   post:
 *     summary: Refresh access token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: New access token generated
 *       400:
 *         description: Refresh token is required
 *       403:
 *         description: Invalid or expired refresh token
 *       500:
 *         description: Internal Server Error
 */
app.post(
  "/refresh-token",
  async (req: express.Request, res: express.Response) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ error: "Refresh token is required" });
      return;
    }

    try {
      const job = await refreshTokenQueue.getJob(refreshToken);

      if (!job) {
        res.status(403).json({ error: "Invalid or expired refresh token" });
        return;
      }

      const { userId } = job.data;
      const user = await prisma.user.findUnique({ where: { id: userId } });

      if (!user) {
        await job.remove(); // Remove job if user not found
        res.status(403).json({ error: "User not found" });
        return;
      }

      const accessToken = generateAccessToken(user);
      const newRefreshToken = generateRefreshToken(user);

      // Remove old refresh token and add new one
      await job.remove();
      await refreshTokenQueue.add(
        "refreshToken",
        {
          userId: user.id,
          refreshToken: newRefreshToken,
        },
        {
          jobId: newRefreshToken,
          removeOnComplete: true,
          removeOnFail: true,
          delay: REFRESH_TOKEN_EXPIRY_MS,
        }
      );

      res.json({ accessToken, refreshToken: newRefreshToken });
    } catch (error) {
      console.error("Error refreshing token", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

// Helper functions for token generation
function generateAccessToken(user: any): string {
  return jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
  });
}

function generateRefreshToken(user: any): string {
  return uuidv4();
}

// Middleware to verify JWT
const authenticateToken: express.RequestHandler = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

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
/**
 * @openapi
 * /protected:
 *   get:
 *     summary: Access protected route
 *     tags: [Protected]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successful response
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 */
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route", user: req.user });
});

// Debug API endpoint to view refresh tokens
/**
 * @openapi
 * /debug/refresh-tokens:
 *   get:
 *     summary: Debug endpoint to view refresh tokens (For development use only)
 *     tags: [Debug]
 *     responses:
 *       200:
 *         description: List of active refresh tokens
 *       500:
 *         description: Internal Server Error
 */
app.get(
  "/debug/refresh-tokens",
  async (req: express.Request, res: express.Response) => {
    if (process.env.NODE_ENV === "production") {
      res
        .status(403)
        .json({ error: "This endpoint is not available in production" });
      return;
    }

    try {
      const jobs = await refreshTokenQueue.getJobs(["delayed"]);
      const tokens = jobs.map((job) => ({
        userId: job.data.userId,
        refreshToken: job.data.refreshToken,
        expiresAt: new Date(job.opts.delay!).toISOString(),
      }));

      res.json({ tokens });
    } catch (error) {
      console.error("Error fetching refresh tokens", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

// Add a processor for the refresh token queue
refreshTokenQueue.process("refreshToken", async (job) => {
  // This job processor will be called when a refresh token expires
  // We don't need to do anything here, as the job will be automatically removed
  console.log(`Refresh token expired and removed: ${job.data.refreshToken}`);
});

// Add this new debug endpoint to clear all refresh tokens
/**
 * @openapi
 * /debug/clear-refresh-tokens:
 *   post:
 *     summary: Clear all refresh tokens (For development use only)
 *     tags: [Debug]
 *     responses:
 *       200:
 *         description: All refresh tokens cleared successfully
 *       403:
 *         description: Not available in production
 *       500:
 *         description: Internal Server Error
 */
app.post('/debug/clear-refresh-tokens', async (req: express.Request, res: express.Response) => {
  if (process.env.NODE_ENV === 'production') {
    res.status(403).json({ error: 'This endpoint is not available in production' });
    return
  }

  try {
    // Get all jobs in the queue
    const jobs = await refreshTokenQueue.getJobs(['delayed', 'waiting', 'active']);

    // Remove all jobs
    await Promise.all(jobs.map(job => job.remove()));

    // Clear the queue
    await refreshTokenQueue.empty();

    res.json({ message: 'All refresh tokens cleared successfully', count: jobs.length });
  } catch (error) {
    console.error('Error clearing refresh tokens', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

// Gracefully shut down the Prisma client and Bull queue when the app is terminated
process.on("SIGINT", async () => {
  await prisma.$disconnect();
  await refreshTokenQueue.close();
  process.exit();
});
