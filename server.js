import express from "express";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import multer from "multer";
import fs from "node:fs";
import { randomUUID } from "node:crypto";

import { Server } from "socket.io";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import Database from "better-sqlite3";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const ROOM_DELETE_PASSWORD = process.env.ROOM_DELETE_PASSWORD;

if (!JWT_SECRET || !ROOM_DELETE_PASSWORD) {
  throw new Error("Задай JWT_SECRET и ROOM_DELETE_PASSWORD");
}

// ==========================================
// DATABASE
// ==========================================

const db = new Database("app.db");

db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    video_url TEXT DEFAULT '',
    is_playing INTEGER DEFAULT 0,
    current_time REAL DEFAULT 0,
    last_update INTEGER DEFAULT 0,
    is_private INTEGER DEFAULT 0,
    password TEXT DEFAULT '',
    FOREIGN KEY(owner_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    text TEXT DEFAULT '',
    type TEXT DEFAULT 'text',
    sticker_id TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(room_id) REFERENCES rooms(id)
  );
`);

// ==========================================
// MIGRATION FOR OLD DATABASE
// ==========================================

function addColumnIfMissing(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();

  const exists = columns.some((item) => item.name === column);

  if (!exists) {
    db.exec(`
      ALTER TABLE ${table}
      ADD COLUMN ${column} ${definition}
    `);

    console.log(`Добавлена колонка ${table}.${column}`);
  }
}

// Если messages была создана старой версией
// сервера — добавляем новые поля автоматически.

addColumnIfMissing("messages", "type", "TEXT DEFAULT 'text'");

addColumnIfMissing("messages", "sticker_id", "TEXT DEFAULT ''");

addColumnIfMissing("users", "avatar_url", "TEXT DEFAULT ''");

// ==========================================
// STICKERS
// ==========================================

const BASE_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;

const stickersDir = path.join(__dirname, "public", "stickers");
fs.mkdirSync(stickersDir, { recursive: true });

db.exec(`
  CREATE TABLE IF NOT EXISTS stickers (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// три старых стикера кладём в таблицу (повторно не добавятся)
const seedSticker = db.prepare(
  "INSERT OR IGNORE INTO stickers (id, filename) VALUES (?, ?)",
);
seedSticker.run("mem1", "alreadysixteen.jpg");
seedSticker.run("mem2", "dima.jpg");
seedSticker.run("mem3", "yosip.jpg");

function getStickerUrl(stickerId) {
  const row = db
    .prepare("SELECT filename FROM stickers WHERE id = ?")
    .get(stickerId);
  return row ? `${BASE_URL}/stickers/${row.filename}` : null;
}

const avatarsDir = path.join(__dirname, "public", "avatars");
fs.mkdirSync(avatarsDir, { recursive: true });

app.use("/avatars", express.static(avatarsDir));

const ALLOWED = {
  "image/jpeg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
};

const upload = multer({
  storage: multer.diskStorage({
    destination: avatarsDir,
    filename: (req, file, cb) =>
      cb(null, `${req.user.userId}-${Date.now()}${ALLOWED[file.mimetype]}`),
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, Boolean(ALLOWED[file.mimetype])),
});

const stickerUpload = multer({
  storage: multer.diskStorage({
    destination: stickersDir,
    filename: (req, file, cb) =>
      cb(null, `${randomUUID()}${ALLOWED[file.mimetype]}`),
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, Boolean(ALLOWED[file.mimetype])),
});

function getAvatarUrl(userId) {
  const row = db
    .prepare("SELECT avatar_url FROM users WHERE id = ?")
    .get(userId);
  return row?.avatar_url || "";
}

// Раздаем папку public/stickers
app.use(
  "/stickers",
  express.static(path.join(__dirname, "public", "stickers")),
);

// ==========================================
// MIDDLEWARE
// ==========================================

app.use(
  cors({
    origin: "*",
  }),
);

app.use(express.json());

// ==========================================
// HELPERS
// ==========================================

function getCalculatedVideoTime(room) {
  if (!room.is_playing) {
    return room.current_time;
  }

  const now = Date.now();

  const elapsedSeconds = (now - room.last_update) / 1000;

  return room.current_time + elapsedSeconds;
}

function generateRoomId() {
  return Math.random().toString(36).substring(2, 9);
}

// ==========================================
// JWT
// ==========================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: "Нет токена",
    });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Нет токена",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      error: "Недействительный токен",
    });
  }
}

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: "Rave backend is running",
  });
});

// ==========================================
// AUTH
// ==========================================

// REGISTER

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Заполните все поля",
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        error: "Логин должен содержать минимум 3 символа",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Пароль должен содержать минимум 6 символов",
      });
    }

    const existingUser = db
      .prepare("SELECT id FROM users WHERE username = ?")
      .get(username);

    if (existingUser) {
      return res.status(400).json({
        error: "Пользователь уже существует",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const stmt = db.prepare(`
      INSERT INTO users (
        username,
        password
      )
      VALUES (?, ?)
    `);

    const info = stmt.run(username, hashedPassword);

    const userId = Number(info.lastInsertRowid);

    const token = jwt.sign(
      {
        userId,
        username,
      },
      JWT_SECRET,
    );

    res.json({
      token,
      username,
      userId,
    });
  } catch (error) {
    console.error("Ошибка регистрации:", error);

    res.status(500).json({
      error: "Ошибка сервера",
    });
  }
});

// LOGIN

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Заполните все поля",
      });
    }

    const user = db
      .prepare("SELECT * FROM users WHERE username = ?")
      .get(username);

    if (!user) {
      return res.status(400).json({
        error: "Неверный логин или пароль",
      });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(400).json({
        error: "Неверный логин или пароль",
      });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
      },
      JWT_SECRET,
    );

    res.json({
      token,
      username: user.username,
      userId: user.id,
    });
  } catch (error) {
    console.error("Ошибка авторизации:", error);

    res.status(500).json({
      error: "Ошибка сервера",
    });
  }
});

// CURRENT USER

app.get("/api/me", authenticateToken, (req, res) => {
  const user = db
    .prepare("SELECT id, username, avatar_url FROM users WHERE id = ?")
    .get(req.user.userId);

  if (!user) return res.status(404).json({ error: "Пользователь не найден" });

  res.json({
    userId: user.id,
    username: user.username,
    avatarUrl: user.avatar_url,
  });
});

app.patch("/api/me", authenticateToken, (req, res) => {
  const username = String(req.body.username || "").trim();

  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: "Ник: от 3 до 30 символов" });
  }

  const taken = db
    .prepare("SELECT id FROM users WHERE username = ? AND id != ?")
    .get(username, req.user.userId);

  if (taken) return res.status(400).json({ error: "Ник уже занят" });

  db.prepare("UPDATE users SET username = ? WHERE id = ?").run(
    username,
    req.user.userId,
  );

  // в старом токене зашит старый ник, поэтому выдаём новый
  const token = jwt.sign({ userId: req.user.userId, username }, JWT_SECRET);
  res.json({ token, username });
});

app.post("/api/me/avatar", authenticateToken, (req, res) => {
  upload.single("avatar")(req, res, (err) => {
    if (err) {
      return res
        .status(400)
        .json({ error: "Файл слишком большой или не картинка" });
    }
    if (!req.file) {
      return res
        .status(400)
        .json({ error: "Нужна картинка jpg, png или webp" });
    }

    const avatarUrl = `/avatars/${req.file.filename}`;
    db.prepare("UPDATE users SET avatar_url = ? WHERE id = ?").run(
      avatarUrl,
      req.user.userId,
    );

    res.json({ avatarUrl });
  });
});

// список всех стикеров
app.get("/api/stickers", authenticateToken, (req, res) => {
  const rows = db
    .prepare(
      `SELECT id, filename FROM stickers
     WHERE user_id IS NULL OR user_id = ?
     ORDER BY rowid`,
    )
    .all(req.user.userId);

  res.json(
    rows.map((row) => ({
      id: row.id,
      url: `${BASE_URL}/stickers/${row.filename}`,
    })),
  );
});

// загрузка нового стикера
app.post("/api/stickers", authenticateToken, (req, res) => {
  stickerUpload.single("sticker")(req, res, (err) => {
    if (err) {
      return res
        .status(400)
        .json({ error: "Файл слишком большой или не картинка" });
    }
    if (!req.file) {
      return res
        .status(400)
        .json({ error: "Нужна картинка jpg, png или webp" });
    }

    const id = randomUUID();
    db.prepare(
      "INSERT INTO stickers (id, filename, user_id) VALUES (?, ?, ?)",
    ).run(id, req.file.filename, req.user.userId);

    res.json({
      data: { id, url: `${BASE_URL}/stickers/${req.file.filename}` },
    });
  });
});

// ==========================================
// ROOMS
// ==========================================

// GET ROOMS

app.get("/api/rooms", authenticateToken, (req, res) => {
  try {
    const rooms = db
      .prepare(
        `
          SELECT
            r.id,
            r.name,
            r.video_url,
            r.is_private,
            r.owner_id,
            u.username AS owner_name
          FROM rooms r
          JOIN users u
            ON r.owner_id = u.id
          ORDER BY r.rowid DESC
        `,
      )
      .all();

    const result = rooms.map((room) => ({
      id: room.id,
      name: room.name,
      video_url: room.video_url,
      is_private: Boolean(room.is_private),
      owner_id: room.owner_id,
      owner_name: room.owner_name,
    }));

    res.json(result);
  } catch (error) {
    console.error("Ошибка получения комнат:", error);

    res.status(500).json({
      error: "Ошибка получения комнат",
    });
  }
});

// CREATE ROOM

app.post("/api/rooms", authenticateToken, async (req, res) => {
  try {
    const { name, isPrivate, password } = req.body;

    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        error: "Укажите название комнаты",
      });
    }

    const roomName = name.trim();

    if (roomName.length > 50) {
      return res.status(400).json({
        error: "Название комнаты слишком длинное",
      });
    }

    if (isPrivate && !password) {
      return res.status(400).json({
        error: "Для приватной комнаты нужен пароль",
      });
    }

    const owner = db
      .prepare("SELECT id FROM users WHERE id = ?")
      .get(req.user.userId);

    if (!owner) {
      return res.status(401).json({
        error: "Пользователь из токена не существует",
      });
    }

    let hashedPassword = "";

    if (isPrivate) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    let roomId;

    // Теоретически коллизия маловероятна,
    // но делаем нормальную проверку.

    do {
      roomId = generateRoomId();
    } while (db.prepare("SELECT id FROM rooms WHERE id = ?").get(roomId));

    const stmt = db.prepare(`
        INSERT INTO rooms (
          id,
          name,
          owner_id,
          video_url,
          is_playing,
          current_time,
          last_update,
          is_private,
          password
        )
        VALUES (?, ?, ?, '', 0, 0, ?, ?, ?)
      `);

    stmt.run(
      roomId,
      roomName,
      req.user.userId,
      Date.now(),
      isPrivate ? 1 : 0,
      hashedPassword,
    );

    res.json({
      id: roomId,
      name: roomName,
      isPrivate: Boolean(isPrivate),
    });
  } catch (error) {
    console.error("ОШИБКА СОЗДАНИЯ КОМНАТЫ:", error);

    res.status(500).json({
      error: "Ошибка создания комнаты",
    });
  }
});

// VERIFY PRIVATE ROOM

app.post("/api/rooms/:id/verify", authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;

    const room = db
      .prepare("SELECT * FROM rooms WHERE id = ?")
      .get(req.params.id);

    if (!room) {
      return res.status(404).json({
        error: "Комната не найдена",
      });
    }

    if (!room.is_private) {
      return res.json({
        success: true,
      });
    }

    const isValid = await bcrypt.compare(password || "", room.password);

    if (!isValid) {
      return res.status(403).json({
        error: "Неверный пароль комнаты",
      });
    }

    res.json({
      success: true,
    });
  } catch (error) {
    console.error("Ошибка проверки комнаты:", error);

    res.status(500).json({
      error: "Ошибка сервера",
    });
  }
});

// DELETE ROOM

app.delete("/api/rooms/:id", authenticateToken, (req, res) => {
  try {
    const { password } = req.body || {};

    const roomId = req.params.id;

    if (password !== ROOM_DELETE_PASSWORD) {
      return res.status(403).json({
        error: "Неверный пароль для удаления",
      });
    }

    const room = db.prepare("SELECT * FROM rooms WHERE id = ?").get(roomId);

    if (!room) {
      return res.status(404).json({
        error: "Комната не найдена",
      });
    }

    // Удалять комнату может только владелец.

    if (room.owner_id !== req.user.userId) {
      return res.status(403).json({
        error: "Вы не являетесь владельцем комнаты",
      });
    }

    const deleteRoom = db.transaction(() => {
      db.prepare("DELETE FROM messages WHERE room_id = ?").run(roomId);

      db.prepare("DELETE FROM rooms WHERE id = ?").run(roomId);
    });

    deleteRoom();

    io.to(roomId).emit("room-deleted", {
      roomId,
    });

    io.in(roomId).socketsLeave(roomId);

    res.json({
      success: true,
    });
  } catch (error) {
    console.error("Ошибка удаления комнаты:", error);

    res.status(500).json({
      error: "Ошибка удаления комнаты",
    });
  }
});

// ==========================================
// SOCKET.IO AUTH
// ==========================================

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token) {
    return next(new Error("Authentication error"));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    socket.user = decoded;

    next();
  } catch {
    next(new Error("Authentication error"));
  }
});

// ==========================================
// SOCKET.IO
// ==========================================

io.on("connection", (socket) => {
  console.log(`Пользователь ${socket.user.username} подключился`);

  // ========================================
  // JOIN ROOM
  // ========================================

  socket.on("join-room", ({ roomId }) => {
    try {
      if (!roomId) {
        return socket.emit("error", {
          message: "Не указан roomId",
        });
      }

      const room = db.prepare("SELECT * FROM rooms WHERE id = ?").get(roomId);

      if (!room) {
        return socket.emit("error", {
          message: "Комната не найдена",
        });
      }

      // Если пользователь уже находится
      // в другой комнате — выходим из нее.

      if (socket.roomId) {
        socket.leave(socket.roomId);
      }

      socket.join(roomId);

      socket.roomId = roomId;

      const currentTime = getCalculatedVideoTime(room);

      const messages = db
        .prepare(
          `
      SELECT
        m.id,
        m.room_id,
        m.user_id,
        u.username,
        u.avatar_url,
        m.text,
        m.type,
        m.sticker_id,
        m.created_at
      FROM messages m
      JOIN users u ON u.id = m.user_id
      WHERE m.room_id = ?
      ORDER BY m.id DESC
      LIMIT 50
    `,
        )
        .all(roomId)
        .reverse();

      const formattedMessages = messages.map((message) => ({
        id: message.id,
        roomId: message.room_id,
        userId: message.user_id,
        username: message.username,
        text: message.text || "",
        type: message.type || "text",
        stickerId: message.sticker_id || "",
        stickerUrl:
          message.type === "sticker" ? getStickerUrl(message.sticker_id) : null,
        created_at: message.created_at,
        avatarUrl: message.avatar_url || "",
      }));

      socket.emit("room-state", {
        roomId: room.id,
        name: room.name,
        ownerId: room.owner_id,
        videoUrl: room.video_url,
        isPlaying: Boolean(room.is_playing),
        currentTime,
        messages: formattedMessages,
      });

      socket.to(roomId).emit("user-joined", {
        userId: socket.user.userId,
        username: socket.user.username,
      });
    } catch (error) {
      console.error("Ошибка join-room:", error);

      socket.emit("error", {
        message: "Ошибка входа в комнату",
      });
    }
  });

  socket.on("typing", () => {
    const roomId = socket.roomId;

    if (!roomId || !socket.rooms.has(roomId)) {
      return;
    }

    socket.to(roomId).emit("user-typing", {
      userId: socket.user.userId,
      username: socket.user.username,
    });
  });

  // ========================================
  // CHANGE VIDEO
  // ========================================

  socket.on("change-video", ({ videoUrl }) => {
    try {
      const roomId = socket.roomId;

      if (!roomId || !socket.rooms.has(roomId)) {
        return;
      }

      const room = db
        .prepare("SELECT owner_id FROM rooms WHERE id = ?")
        .get(roomId);

      if (!room) {
        return;
      }

      // Только владелец комнаты.

      if (room.owner_id !== socket.user.userId) {
        return;
      }

      if (typeof videoUrl !== "string") {
        return;
      }

      db.prepare(
        `
          UPDATE rooms
          SET
            video_url = ?,
            is_playing = 0,
            current_time = 0,
            last_update = ?
          WHERE id = ?
        `,
      ).run(videoUrl, Date.now(), roomId);

      io.to(roomId).emit("video-changed", {
        videoUrl,
        currentTime: 0,
        isPlaying: false,
      });
    } catch (error) {
      console.error("Ошибка change-video:", error);
    }
  });

  // ========================================
  // MEDIA CONTROL
  // ========================================

  socket.on("media-control", ({ action, currentTime }) => {
    try {
      const roomId = socket.roomId;

      if (!roomId || !socket.rooms.has(roomId)) {
        return;
      }

      const room = db
        .prepare("SELECT owner_id, is_playing FROM rooms WHERE id = ?")
        .get(roomId);

      if (!room) {
        return;
      }

      // Только владелец.
      if (room.owner_id !== socket.user.userId) {
        return;
      }

      if (!["play", "pause", "seek"].includes(action)) {
        return;
      }

      if (
        typeof currentTime !== "number" ||
        !Number.isFinite(currentTime) ||
        currentTime < 0
      ) {
        return;
      }

      // play и pause меняют состояние, seek оставляет как было
      let isPlaying = Boolean(room.is_playing);
      if (action === "play") isPlaying = true;
      if (action === "pause") isPlaying = false;

      db.prepare(
        `
        UPDATE rooms
        SET
          is_playing = ?,
          current_time = ?,
          last_update = ?
        WHERE id = ?
      `,
      ).run(isPlaying ? 1 : 0, currentTime, Date.now(), roomId);

      socket.to(roomId).emit("media-state-update", {
        action,
        currentTime,
        isPlaying,
        updatedBy: socket.user.username,
      });
    } catch (error) {
      console.error("Ошибка media-control:", error);
    }
  });

  // ========================================
  // SEND TEXT MESSAGE
  // ========================================

  socket.on("send-message", ({ type = "text", text = "", stickerId = "" }) => {
    console.log("Получил:", {
      type,
      text,
      stickerId,
    });
    try {
      const roomId = socket.roomId;

      if (!roomId || !socket.rooms.has(roomId)) {
        return;
      }

      // -------------------------------
      // TEXT
      // -------------------------------

      if (type === "text") {
        if (typeof text !== "string" || !text.trim()) {
          return;
        }

        const cleanText = text.trim();

        if (cleanText.length > 1000) {
          return;
        }

        const stmt = db.prepare(`
            INSERT INTO messages (
              room_id,
              user_id,
              username,
              text,
              type,
              sticker_id
            )
            VALUES (?, ?, ?, ?, 'text', '')
          `);

        const info = stmt.run(
          roomId,
          socket.user.userId,
          socket.user.username,
          cleanText,
        );

        const messageData = {
          id: Number(info.lastInsertRowid),
          roomId,
          userId: socket.user.userId,
          username: socket.user.username,
          text: cleanText,
          type: "text",
          stickerId: "",
          stickerUrl: null,
          created_at: new Date().toISOString(),
          avatarUrl: getAvatarUrl(socket.user.userId),
        };

        console.log("Отправляю в комнату:", messageData);

        io.to(roomId).emit("new-message", messageData);

        return;
      }

      // -------------------------------
      // STICKER
      // -------------------------------

      if (type === "sticker") {
        if (typeof stickerId !== "string") return;

        const allowed = db
          .prepare(
            "SELECT 1 FROM stickers WHERE id = ? AND (user_id IS NULL OR user_id = ?)",
          )
          .get(stickerId, socket.user.userId);
        if (!allowed) return;

        const stickerUrl = getStickerUrl(stickerId);
        if (!stickerUrl) return;
        // ...дальше как было

        const stmt = db.prepare(`
            INSERT INTO messages (
              room_id,
              user_id,
              username,
              text,
              type,
              sticker_id
            )
            VALUES (?, ?, ?, '', 'sticker', ?)
          `);

        const info = stmt.run(
          roomId,
          socket.user.userId,
          socket.user.username,
          stickerId,
        );

        const messageData = {
          id: Number(info.lastInsertRowid),
          roomId,
          userId: socket.user.userId,
          username: socket.user.username,
          text: "",
          type: "sticker",
          stickerId,
          stickerUrl: stickerUrl,
          created_at: new Date().toISOString(),
          avatarUrl: getAvatarUrl(socket.user.userId),
        };

        io.to(roomId).emit("new-message", messageData);
      }
    } catch (error) {
      console.error("Ошибка send-message:", error);
    }
  });

  socket.on("disconnect", () => {
    if (socket.roomId) {
      socket.to(socket.roomId).emit("user-left", {
        userId: socket.user.userId,
        username: socket.user.username,
      });
    }

    console.log(`Пользователь ${socket.user.username} отключился`);
  });
});

app.use((err, req, res, next) => {
  console.error("Express error:", err);

  res.status(500).json({
    error: "Ошибка сервера",
  });
});

server.listen(PORT, () => {
  console.log(`Rave backend запущен на http://localhost:${PORT}`);
});
