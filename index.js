import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import * as crypto from 'crypto';
import sqlite3 from 'sqlite3';
import jwt from 'jsonwebtoken';
import { getActivePublicKey } from './jwt-utils.js';
import bodyParser from 'body-parser';
import cors from 'cors';

const NONCE_EXPIRY_MS = 5 * 60 * 1000;

/** @type {sqlite3.Database} */
const db = new sqlite3.Database('db.sqlite');

db.serialize(() => {
  db.run(`
CREATE TABLE IF NOT EXISTS users (
shotdeck_token STRING NOT NULL,
canva_id INTEGER NOT NULL UNIQUE
)
`);
});

const app = express();

app.use(cookieParser(process.env.COOKIE_SIGNING_KEY));
app.use(bodyParser.json());
app.use(cors({ origin: process.env.CANVA_CORS_ORIGIN }));

app.get('/login', async (req, res) => {
  const nonceQuery = req.query.nonce;
  const nonceWithExpiryCookie = req.signedCookies.nonceWithExpiry;
  res.clearCookie('nonceWithExpiry');

  try {
    const [nonceCookie, nonceExpiry] = JSON.parse(nonceWithExpiryCookie);

    if (
      Date.now() > nonceExpiry || // The nonce has expired
      typeof nonceCookie !== 'string' || // The nonce in the cookie is not a string
      typeof nonceQuery !== 'string' || // The nonce in the query parameter is not a string
      nonceCookie.length < 1 || // The nonce in the cookie is an empty string
      nonceQuery.length < 1 || // The nonce in the query parameter is an empty string
      nonceCookie !== nonceQuery // The nonce in the cookie does not match the nonce in the query parameter
    ) {
      const params = new URLSearchParams({
        success: 'false',
        state: req.query.state,
        errors: 'invalid_nonce',
      });

      return res.redirect(
        302,
        `https://www.canva.com/apps/configured?${params.toString()}`
      );
    }

    const canvaToken = req.query.canva_user_token;

    const publicKey = await getActivePublicKey({
      appId: process.env.CANVA_APP_ID,
      token: canvaToken
    });

    const verified = jwt.verify(canvaToken, publicKey, {
      audience: process.env.CANVA_APP_ID
    });

    if (!verified.aud || !verified.brandId || !verified.userId) {
      throw new Error('The user token is not valid');
    }

    // Proxy to shotdeck API
    const formData = new FormData();
    formData.append('email', process.env.USERNAME);
    formData.append('password', process.env.PASSWORD);

    const response = await fetch('https://stage.shotdeck.com/api/login', {
      method: 'POST',
      headers: {
        'X-API-KEY': process.env.SHOTDECK_APP_ID
      },
      body: formData
    });

    if (response.ok) {
      const { data: { token } } = await response.json();

      db.run('INSERT INTO users VALUES($shotdeckToken, $canvaId)', [token, verified.userId]);

      const params = new URLSearchParams({
        success: 'true',
        state: req.query.state,
      });

      res.redirect(
        302,
        `https://www.canva.com/apps/configured?${params.toString()}`
      );
    } else {
      const { message } = await response.json();

      const params = new URLSearchParams({
        success: 'false',
        state: req.query.state,
        errors: message,
      });

      return res.redirect(
        302,
        `https://www.canva.com/apps/configured?${params.toString()}`
      );
    }
  } catch (e) {
    // An unexpected error has occurred (e.g. JSON parsing error)
    const params = new URLSearchParams({
      success: 'false',
      state: req.query.state,
      errors: JSON.stringify(e instanceof Error ? e.message : 'UNKNOWN'),
    });

    return res.redirect(
      302,
      `https://www.canva.com/apps/configured?${params.toString()}`
    );
  }
});

app.post('/canva-login', async (req, res) => {
  const { token: canvaToken } = req.body;

  const publicKey = await getActivePublicKey({
    appId: process.env.CANVA_APP_ID,
    token: canvaToken
  });

  const verified = jwt.verify(canvaToken, publicKey, {
    audience: process.env.CANVA_APP_ID
  });

  if (!verified.aud || !verified.brandId || !verified.userId) {
    throw new Error('The user token is not valid');
  }

  const canvaId = verified.userId;

  db.get('SELECT shotdeck_token FROM users WHERE canva_id = $canvaId', [canvaId], (err, row) => {
    if (err || !row) {
      res.send(JSON.stringify({ success: false, err: err ? JSON.stringify(err) : 'Not connected' }));
    } else {
      res.send(JSON.stringify({ success: true, token: row.shotdeck_token }));
    }
  });
});

app.get('/decks', async (req, res) => {
  const { 'x-auth-token': token } = req.headers;

  const response = await fetch('https://stage.shotdeck.com/api/decks/', {
    headers: {
      'X-API-KEY': process.env.SHOTDECK_APP_ID,
      'X-AUTH-TOKEN': token
    }
  });

  if (response.ok) {
    const { data: { decks } } = (await response.json());

    res.send(JSON.stringify({ decks }));
  } else {
    const err = await response.json();

    res.send(JSON.stringify({ err }));
  }
});

app.get('/configuration/start', (req, res) => {
  const { state } = req.query;

  const nonce = crypto.randomUUID();

  // Create an expiry time for the nonce
  const nonceExpiry = Date.now() + NONCE_EXPIRY_MS;

  // Store the nonce and expiry time in a stringified JSON array
  const nonceWithExpiry = JSON.stringify([nonce, nonceExpiry]);

  // Store the nonce and expiry time in a cookie
  res.cookie('nonceWithExpiry', nonceWithExpiry, {
    httpOnly: true,
    secure: true,
    signed: true,
    maxAge: NONCE_EXPIRY_MS,
  });

  // Create query parameters
  const params = new URLSearchParams({
    state,
    nonce,
  });

  // Redirect the user
  res.redirect(
    302,
    `https://www.canva.com/apps/configure/link?${params.toString()}`
  );
});

app.post('/configuration/delete', async (req, res) => {
  const { authorization: authHeader } = req.headers;
  const token = authHeader.replace(/Bearer (.*)/, '$1');

  const publicKey = await getActivePublicKey({
    appId: process.env.CANVA_APP_ID,
    token: token
  });

  const verified = jwt.verify(token, publicKey, {
    audience: process.env.CANVA_APP_ID
  });

  if (!verified.aud || !verified.brandId || !verified.userId) {
    throw new Error('The user token is not valid');
  }

  const canvaId = verified.userId;

  db.run('DELETE FROM users WHERE canva_id = $canvaId', [canvaId]);

  res.send(JSON.stringify({ type: 'SUCCESS' }));
});

const port = process.env.SERVER_PORT || 3000;

const server = app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

const shutdown = () => {
  console.debug('SIGTERM or SIGINT signal received: closing HTTP server');
  try {
    db.close();
  } catch (e) {
    console.log(JSON.stringify(e));
  }
  server.close(() => {
    console.debug('HTTP server closed');
  });
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
