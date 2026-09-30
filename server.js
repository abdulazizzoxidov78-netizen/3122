require('dotenv').config();

const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();

const PORT = process.env.PORT || 4322;

const MONGO_URI = process.env.MONGO_URI;

const JWT_SECRET =
  process.env.JWT_SECRET || 'only-for-local-development-change-me';

const JWT_EXPIRES_IN =
  process.env.JWT_EXPIRES_IN || '5m';

const REFRESH_SECRET =
  process.env.REFRESH_SECRET ||
  'only-for-local-development-refresh-change-me';

const REFRESH_EXPIRES_IN =
  process.env.REFRESH_EXPIRES_IN || '7d';


// =========================
// EXPRESS
// =========================

// CORS
app.use(cors());

// JSON
app.use(express.json());


// =========================
// MONGODB USER MODEL
// =========================

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    passwordHash: {
      type: String,
      required: true
    },

    firstName: {
      type: String,
      required: true,
      trim: true
    },

    lastName: {
      type: String,
      required: true,
      trim: true
    },

    username: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },

    role: {
      type: String,
      default: 'user'
    },

    phone: {
      type: String,
      default: null
    },

    avatarUrl: {
      type: String,
      default: null
    },

    dateOfBirth: {
      type: String,
      default: null
    },

    gender: {
      type: String,
      default: null
    },

    address: {
      city: {
        type: String,
        default: null
      },

      district: {
        type: String,
        default: null
      },

      country: {
        type: String,
        default: null
      }
    },

    isVerified: {
      type: Boolean,
      default: false
    },

    isActive: {
      type: Boolean,
      default: true
    },

    lastLoginAt: {
      type: Date,
      default: null
    }
  },

  {
    timestamps: true
  }
);

const User = mongoose.model('User', userSchema);


// =========================
// SWAGGER
// =========================

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.3',

    info: {
      title: 'Users Authentication API',
      version: '1.0.0',
      description:
        'JWT orqali register, login, refresh token va profil ma’lumotlarini olish API si.'
    },

    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Local server'
      },
      {
        url: 'https://three122-1.onrender.com',
        description: 'Global server'
      }
    ],

    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },

      schemas: {
        RegisterRequest: {
          type: 'object',

          required: [
            'email',
            'password',
            'firstName',
            'lastName',
            'username'
          ],

          properties: {
            email: {
              type: 'string',
              format: 'email',
              example: 'ali@example.com'
            },

            password: {
              type: 'string',
              format: 'password',
              example: 'Ali12345'
            },

            firstName: {
              type: 'string',
              example: 'Ali'
            },

            lastName: {
              type: 'string',
              example: 'Karimov'
            },

            username: {
              type: 'string',
              example: 'alikarimov'
            },

            role: {
              type: 'string',
              example: 'user'
            },

            phone: {
              type: 'string',
              example: '+998901234567'
            },

            avatarUrl: {
              type: 'string',
              format: 'uri',
              example: 'https://i.pravatar.cc/300'
            },

            dateOfBirth: {
              type: 'string',
              format: 'date',
              example: '2000-01-01'
            },

            gender: {
              type: 'string',
              example: 'male'
            }
          }
        },

        LoginRequest: {
          type: 'object',

          required: [
            'email',
            'password'
          ],

          properties: {
            email: {
              type: 'string',
              format: 'email',
              example: 'ali@example.com'
            },

            password: {
              type: 'string',
              format: 'password',
              example: 'Ali12345'
            }
          }
        },

        RefreshRequest: {
          type: 'object',

          required: [
            'refreshToken'
          ],

          properties: {
            refreshToken: {
              type: 'string',
              example:
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            }
          }
        },

        User: {
          type: 'object',

          properties: {
            id: {
              type: 'string',
              example: '68cabc123456789'
            },

            email: {
              type: 'string',
              example: 'ali@example.com'
            },

            firstName: {
              type: 'string',
              example: 'Ali'
            },

            lastName: {
              type: 'string',
              example: 'Karimov'
            },

            username: {
              type: 'string',
              example: 'alikarimov'
            },

            role: {
              type: 'string',
              example: 'admin'
            },

            phone: {
              type: 'string',
              example: '+998901234567'
            },

            avatarUrl: {
              type: 'string',
              format: 'uri'
            },

            dateOfBirth: {
              type: 'string',
              format: 'date'
            },

            gender: {
              type: 'string',
              example: 'male'
            },

            isVerified: {
              type: 'boolean'
            },

            isActive: {
              type: 'boolean'
            },

            createdAt: {
              type: 'string',
              format: 'date-time'
            },

            lastLoginAt: {
              type: 'string',
              format: 'date-time',
              nullable: true
            }
          }
        }
      }
    }
  },

  apis: [__filename]
});

app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec)
);


// =========================
// REFRESH TOKEN STORE
// =========================

const refreshTokenStore = new Map();


// =========================
// PUBLIC USER
// =========================

function publicUser(user) {
  return {
    id: user._id.toString(),

    email: user.email,

    firstName: user.firstName,

    lastName: user.lastName,

    username: user.username,

    role: user.role,

    phone: user.phone,

    avatarUrl: user.avatarUrl,

    dateOfBirth: user.dateOfBirth,

    gender: user.gender,

    address: user.address,

    isVerified: user.isVerified,

    isActive: user.isActive,

    createdAt: user.createdAt,

    lastLoginAt: user.lastLoginAt
  };
}


// =========================
// ACCESS TOKEN
// =========================

function issueAccessToken(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      email: user.email,
      role: user.role
    },

    JWT_SECRET,

    {
      expiresIn: JWT_EXPIRES_IN
    }
  );
}


// =========================
// REFRESH TOKEN
// =========================

function issueRefreshToken(user) {
  const jti = crypto.randomUUID();

  const userId = user._id.toString();

  const refreshToken = jwt.sign(
    {
      sub: userId,
      jti
    },

    REFRESH_SECRET,

    {
      expiresIn: REFRESH_EXPIRES_IN
    }
  );

  if (!refreshTokenStore.has(userId)) {
    refreshTokenStore.set(userId, new Set());
  }

  refreshTokenStore.get(userId).add(jti);

  return refreshToken;
}


function revokeRefreshToken(userId, jti) {
  const set = refreshTokenStore.get(userId);

  if (set) {
    set.delete(jti);
  }
}


function isRefreshTokenActive(userId, jti) {
  const set = refreshTokenStore.get(userId);

  return Boolean(
    set && set.has(jti)
  );
}


// =========================
// AUTH MIDDLEWARE
// =========================

function requireAuth(req, res, next) {
  const authorization =
    req.headers.authorization;

  if (
    !authorization ||
    !authorization.startsWith('Bearer ')
  ) {
    return res.status(401).json({
      message: 'Bearer token yuboring.'
    });
  }

  const token = authorization.slice(7);

  try {
    req.auth = jwt.verify(
      token,
      JWT_SECRET
    );

    next();

  } catch (error) {

    return res.status(401).json({
      message:
        'Token yaroqsiz yoki muddati tugagan.'
    });
  }
}


// =========================
// HOME
// =========================

/**
 * @swagger
 * /:
 *   get:
 *     summary: API holatini tekshirish
 *     responses:
 *       200:
 *         description: API ishlamoqda
 */

app.get('/', (req, res) => {
  res.json({
    message: 'API ishlayapti',

    endpoints: [
      'POST /register',
      'POST /login',
      'GET /me',
      'POST /refresh',
      'POST /logout'
    ]
  });
});


// =========================
// REGISTER
// =========================

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Yangi foydalanuvchi ro'yxatdan o'tkazish
 *     tags: [Authentication]
 *
 *     requestBody:
 *       required: true
 *
 *       content:
 *         application/json:
 *
 *           schema:
 *             $ref: '#/components/schemas/RegisterRequest'
 *
 *     responses:
 *       201:
 *         description: Foydalanuvchi muvaffaqiyatli ro'yxatdan o'tdi
 *
 *       400:
 *         description: Majburiy ma'lumotlar yuborilmagan
 *
 *       409:
 *         description: Email yoki username allaqachon mavjud
 */

app.post('/register', async (req, res) => {
  try {
    const {
      email,
      password,
      firstName,
      lastName,
      username,
      role,
      phone,
      avatarUrl,
      dateOfBirth,
      gender
    } = req.body;

    if (
      !email ||
      !password ||
      !firstName ||
      !lastName ||
      !username
    ) {
      return res.status(400).json({
        message:
          'email, password, firstName, lastName va username majburiy.'
      });
    }

    const existingEmail =
      await User.findOne({
        email: email.toLowerCase()
      });

    if (existingEmail) {
      return res.status(409).json({
        message:
          'Bu email allaqachon mavjud.'
      });
    }

    const existingUsername =
      await User.findOne({
        username: username.toLowerCase()
      });

    if (existingUsername) {
      return res.status(409).json({
        message:
          'Bu username allaqachon mavjud.'
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 10);

    const newUser = await User.create({
      email: email.toLowerCase(),

      passwordHash,

      firstName,

      lastName,

      username: username.toLowerCase(),

      role: role || 'user',

      phone: phone || null,

      avatarUrl: avatarUrl || null,

      dateOfBirth: dateOfBirth || null,

      gender: gender || null,

      address: {
        city: null,
        district: null,
        country: null
      },

      isVerified: false,

      isActive: true
    });

    console.log(
      `✅ Yangi user MongoDB ga saqlandi: ${newUser.email}`
    );

    return res.status(201).json({
      message:
        'Ro‘yxatdan o‘tish muvaffaqiyatli.',

      user: publicUser(newUser)
    });

  } catch (error) {

    console.error(
      '❌ Register xatosi:',
      error.message
    );

    return res.status(500).json({
      message:
        'Serverda xatolik yuz berdi.'
    });
  }
});


// =========================
// LOGIN
// =========================

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login qilish va JWT access + refresh token olish
 *     tags: [Authentication]
 *
 *     requestBody:
 *       required: true
 *
 *       content:
 *         application/json:
 *
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *
 *     responses:
 *       200:
 *         description: Login muvaffaqiyatli
 *
 *       400:
 *         description: Email yoki password yuborilmagan
 *
 *       401:
 *         description: Email yoki parol xato
 *
 *       403:
 *         description: Foydalanuvchi faol emas
 */

app.post('/login', async (req, res) => {
  try {

    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message:
          'email va password majburiy.'
      });
    }

    const user = await User.findOne({
      email: email.toLowerCase()
    });

    if (
      !user ||
      !(await bcrypt.compare(
        password,
        user.passwordHash
      ))
    ) {
      return res.status(401).json({
        message:
          'Email yoki parol xato.'
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        message:
          'Foydalanuvchi faol emas.'
      });
    }

    user.lastLoginAt = new Date();

    await user.save();

    const accessToken =
      issueAccessToken(user);

    const refreshToken =
      issueRefreshToken(user);

    console.log(
      `✅ Login MongoDB user: ${user.email}`
    );

    res.json({
      message:
        'Login muvaffaqiyatli.',

      tokenType: 'Bearer',

      accessToken,

      expiresIn:
        JWT_EXPIRES_IN,

      refreshToken,

      refreshExpiresIn:
        REFRESH_EXPIRES_IN,

      user: publicUser(user)
    });

  } catch (error) {

    console.error(
      '❌ Login xatosi:',
      error.message
    );

    res.status(500).json({
      message:
        'Serverda xatolik yuz berdi.'
    });
  }
});


// =========================
// REFRESH
// =========================

/**
 * @swagger
 * /refresh:
 *   post:
 *     summary: Access tokenni yangilash
 *     tags: [Authentication]
 *
 *     requestBody:
 *       required: true
 *
 *       content:
 *         application/json:
 *
 *           schema:
 *             $ref: '#/components/schemas/RefreshRequest'
 *
 *     responses:
 *       200:
 *         description: Token yangilandi
 *
 *       400:
 *         description: refreshToken yuborilmagan
 *
 *       401:
 *         description: refreshToken yaroqsiz
 */

app.post('/refresh', async (req, res) => {
  try {

    const {
      refreshToken
    } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        message:
          'refreshToken majburiy.'
      });
    }

    let payload;

    try {

      payload = jwt.verify(
        refreshToken,
        REFRESH_SECRET
      );

    } catch (error) {

      return res.status(401).json({
        message:
          'refreshToken yaroqsiz yoki muddati tugagan.'
      });
    }

    if (
      !isRefreshTokenActive(
        payload.sub,
        payload.jti
      )
    ) {
      return res.status(401).json({
        message:
          'refreshToken bekor qilingan. Qaytadan login qiling.'
      });
    }

    const user =
      await User.findById(payload.sub);

    if (!user || !user.isActive) {
      return res.status(401).json({
        message:
          'Foydalanuvchi topilmadi yoki faol emas.'
      });
    }

    revokeRefreshToken(
      payload.sub,
      payload.jti
    );

    const newAccessToken =
      issueAccessToken(user);

    const newRefreshToken =
      issueRefreshToken(user);

    res.json({
      message:
        'Token yangilandi.',

      tokenType: 'Bearer',

      accessToken:
        newAccessToken,

      expiresIn:
        JWT_EXPIRES_IN,

      refreshToken:
        newRefreshToken,

      refreshExpiresIn:
        REFRESH_EXPIRES_IN
    });

  } catch (error) {

    console.error(
      '❌ Refresh xatosi:',
      error.message
    );

    res.status(500).json({
      message:
        'Serverda xatolik yuz berdi.'
    });
  }
});


// =========================
// LOGOUT
// =========================

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: Logout qilish
 *     tags: [Authentication]
 *
 *     requestBody:
 *       required: true
 *
 *       content:
 *         application/json:
 *
 *           schema:
 *             $ref: '#/components/schemas/RefreshRequest'
 *
 *     responses:
 *       200:
 *         description: Muvaffaqiyatli chiqildi
 *
 *       400:
 *         description: refreshToken yuborilmagan
 *
 *       401:
 *         description: refreshToken yaroqsiz
 */

app.post('/logout', (req, res) => {

  const {
    refreshToken
  } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      message:
        'refreshToken majburiy.'
    });
  }

  try {

    const payload =
      jwt.verify(
        refreshToken,
        REFRESH_SECRET
      );

    revokeRefreshToken(
      payload.sub,
      payload.jti
    );

  } catch (error) {

    return res.status(401).json({
      message:
        'refreshToken yaroqsiz.'
    });
  }

  res.json({
    message:
      'Muvaffaqiyatli chiqdingiz.'
  });
});


// =========================
// ME
// =========================

/**
 * @swagger
 * /me:
 *   get:
 *     summary: Joriy foydalanuvchi profilini olish
 *     tags: [Authentication]
 *
 *     security:
 *       - bearerAuth: []
 *
 *     responses:
 *       200:
 *         description: Foydalanuvchi ma'lumotlari
 *
 *       401:
 *         description: Token noto'g'ri yoki yuborilmagan
 *
 *       404:
 *         description: Foydalanuvchi topilmadi
 */

app.get(
  '/me',
  requireAuth,
  async (req, res) => {

    try {

      const user =
        await User.findById(
          req.auth.sub
        );

      if (!user) {
        return res.status(404).json({
          message:
            'Foydalanuvchi topilmadi.'
        });
      }

      res.json({
        user: publicUser(user)
      });

    } catch (error) {

      console.error(
        '❌ /me xatosi:',
        error.message
      );

      res.status(500).json({
        message:
          'Serverda xatolik yuz berdi.'
      });
    }
  }
);


// =========================
// 404
// =========================

app.use((req, res) => {
  res.status(404).json({
    message:
      'Route topilmadi.'
  });
});


// =========================
// START SERVER
// =========================

async function startServer() {

  try {

    if (!MONGO_URI) {

      console.error(
        '❌ MongoDB ishlamayapti: MONGO_URI .env faylda topilmadi.'
      );

      process.exit(1);
    }

    await mongoose.connect(
      MONGO_URI
    );

    console.log(
      '===================================='
    );

    console.log(
      '✅ MongoDB ishlayapti va ulandi'
    );

    console.log(
      `📦 Database: ${mongoose.connection.name}`
    );

    console.log(
      '===================================='
    );

    app.listen(
      PORT,
      () => {

        console.log(
          `🚀 Server http://localhost:${PORT} da ishlayapti`
        );

        console.log(
          `📚 Swagger http://localhost:${PORT}/api-docs`
        );

        console.log(
          '===================================='
        );
      }
    );

  } catch (error) {

    console.error(
      '===================================='
    );

    console.error(
      '❌ MongoDB ISHLAMAYAPTI!'
    );

    console.error(
      '❌ MongoDB ga ulanishda xato:'
    );

    console.error(
      error.message
    );

    console.error(
      '===================================='
    );

    process.exit(1);
  }
}


startServer();