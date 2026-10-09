const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-change-me';
const KEY = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY || JWT_SECRET).digest();

const DB = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
}) : null;

const FALLBACK_FILE = path.join(__dirname, 'fallback.json');

const ENVIRONMENTS = {
  test: {
    oauth: 'https://mow-acc.api.vlaanderen.be/oauth/token',
    trip: 'https://mow-acc.api.vlaanderen.be/chiron/taxirit',
    hello: 'https://mow-acc.api.vlaanderen.be/chiron/hello'
  },
  production: {
    oauth: 'https://mow.api.vlaanderen.be/oauth/token',
    trip: 'https://mow.api.vlaanderen.be/chiron/taxirit'
  }
};

const COLLECTIONS = ['drivers', 'vehicles', 'customers', 'invoices'];
const READ_COLLECTIONS = ['companies', 'trips', 'messages', 'audit'].concat(COLLECTIONS);

const blankState = () => ({
  companies: [], drivers: [], vehicles: [], customers: [],
  trips: [], invoices: [], messages: [], audit: []
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '500kb' }));

function encryptValue(value) {
  if (!value) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const encrypted = cipher.update(value, 'utf8', 'base64') + cipher.final('base64');
  return [iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted].join('.');
}

function decryptValue(value) {
  try {
    const [iv, tag, encrypted] = value.split('.');
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    return decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8');
  } catch { return ''; }
}

async function getState() {
  if (!DB) {
    try { return JSON.parse(fs.readFileSync(FALLBACK_FILE, 'utf8')); }
    catch { return blankState(); }
  }
  const result = await DB.query('SELECT data FROM golden_state WHERE id = 1');
  return result.rows[0]?.data || blankState();
}

async function saveState(state) {
  if (!DB) {
    fs.writeFileSync(FALLBACK_FILE, JSON.stringify(state, null, 2));
    return;
  }
  await DB.query(
    `INSERT INTO golden_state (id, data) VALUES (1, $1)
     ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()`,
    [state]
  );
}

function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}

function addAudit(state, action, type, itemId) {
  state.audit.push({ id: crypto.randomUUID(), action, type, itemId, at: new Date().toISOString() });
}

async function getAccessToken(company, environment) {
  const c = company.chiron?.[environment];
  if (!c?.clientId || !c?.secret) throw new Error('Client ID أو Client Secret غير موجودين');
  const basic = Buffer.from(c.clientId + ':' + decryptValue(c.secret)).toString('base64');
  const r = await axios.post(ENVIRONMENTS[environment].oauth, 'grant_type=client_credentials', {
    headers: { Authorization: 'Basic ' + basic, 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 15000
  });
  return r.data.access_token;
}

function buildChironPayload(trip, status) {
  const payload = {
    taxibedrijf: { aanbieder: { registratie: trip.kbo, naam: trip.companyName } },
    voertuig: { nummerplaat: trip.plate },
    uitvoerder: { bestuurderspasnummer: trip.driverCard },
    vertrektijdstip: trip.startedAt,
    vertrekpunt: { lengtegraad: Number(trip.startLng), breedtegraad: Number(trip.startLat) }
  };
  if (status === 'aankomst') {
    payload.aankomsttijdstip = trip.endedAt;
    payload.aankomstpunt = { lengtegraad: Number(trip.endLng), breedtegraad: Number(trip.endLat) };
    payload.afstand = { waarde: Number(trip.distanceKm) };
    payload.kostprijs = { waarde: Number(trip.price) };
  }
  return { status, ritnummer: trip.tripNumber, rit: payload, broncreatiedatum: new Date().toISOString() };
}

app.get('/api/health', (req, res) => res.json({ ok: true, database: Boolean(DB) }));

app.post('/api/login', (req, res) => {
  const password = String(req.body.password || '');
  const expected = process.env.ADMIN_PASSWORD || '';
  const hash = process.env.ADMIN_PASSWORD_HASH || '';
  let ok = false;
  if (expected && password === expected) ok = true;
  else if (hash && bcrypt.compareSync(password, hash)) ok = true;
  if (!ok) return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }) });
});

app.get('/api/:type', requireAuth, async (req, res) => {
  if (!READ_COLLECTIONS.includes(req.params.type)) return res.status(404).json({ error: 'Not found' });
  const state = await getState();
  let items = state[req.params.type];
  if (req.params.type === 'companies') {
    items = items.map(c => ({
      ...c,
      chiron: {
        test: { clientId: c.chiron?.test?.clientId || '', configured: Boolean(c.chiron?.test?.secret) },
        production: { clientId: c.chiron?.production?.clientId || '', configured: Boolean(c.chiron?.production?.secret) }
      }
    }));
  }
  res.json(items);
});

app.post('/api/companies', requireAuth, async (req, res) => {
  const state = await getState();
  const b = req.body;
  if (!b.name || !b.kbo) return res.status(400).json({ error: 'اسم الشركة و KBO مطلوبان' });
  const company = {
    id: crypto.randomUUID(), name: b.name, kbo: b.kbo, address: b.address || '',
    email: b.email || '', phone: b.phone || '',
    chiron: {
      test: { clientId: b.testClientId || '', secret: encryptValue(b.testSecret || '') },
      production: { clientId: b.productionClientId || '', secret: encryptValue(b.productionSecret || '') }
    },
    createdAt: new Date().toISOString()
  };
  state.companies.push(company);
  addAudit(state, 'create', 'company', company.id);
  await saveState(state);
  res.status(201).json({ id: company.id });
});

app.put('/api/companies/:id/chiron', requireAuth, async (req, res) => {
  const state = await getState();
  const company = state.companies.find(x => x.id === req.params.id);
  const b = req.body;
  if (!company) return res.status(404).json({ error: 'الشركة غير موجودة' });
  if (!['test', 'production'].includes(b.environment)) return res.status(400).json({ error: 'بيئة غير صحيحة' });
  company.chiron[b.environment] = {
    clientId: b.clientId || '',
    secret: b.secret ? encryptValue(b.secret) : company.chiron[b.environment]?.secret || ''
  };
  addAudit(state, 'update_credentials', b.environment, company.id);
  await saveState(state);
  res.json({ ok: true });
});

app.post('/api/chiron/:companyId/hello', requireAuth, async (req, res) => {
  try {
    const state = await getState();
    const company = state.companies.find(x => x.id === req.params.companyId);
    if (!company) return res.status(404).json({ error: 'الشركة غير موجودة' });
    if ((req.body.environment || 'test') !== 'test') return res.status(400).json({ error: 'hello متاح في TEST فقط' });
    const c = company.chiron.test;
    const basic = Buffer.from(c.clientId + ':' + decryptValue(c.secret)).toString('base64');
    const r = await axios.get(ENVIRONMENTS.test.hello, { headers: { Authorization: 'Basic ' + basic }, timeout: 15000 });
    res.json({ ok: true, response: r.data });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.response?.data || e.message });
  }
});

app.post('/api/:type', requireAuth, async (req, res) => {
  const type = req.params.type;
  if (!COLLECTIONS.includes(type)) return res.status(404).json({ error: 'Not found' });
  const state = await getState();
  const item = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), ...req.body };
  state[type].push(item);
  addAudit(state, 'create', type, item.id);
  await saveState(state);
  res.status(201).json(item);
});

app.put('/api/:type/:id', requireAuth, async (req, res) => {
  const type = req.params.type;
  if (!COLLECTIONS.includes(type)) return res.status(404).json({ error: 'Not found' });
  const state = await getState();
  const item = state[type].find(x => x.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'غير موجود' });
  Object.assign(item, req.body, { id: item.id });
  addAudit(state, 'update', type, item.id);
  await saveState(state);
  res.json(item);
});

app.delete('/api/:type/:id', requireAuth, async (req, res) => {
  const type = req.params.type;
  if (!COLLECTIONS.includes(type)) return res.status(404).json({ error: 'Not found' });
  const state = await getState();
  state[type] = state[type].filter(x => x.id !== req.params.id);
  addAudit(state, 'delete', type, req.params.id);
  await saveState(state);
  res.json({ ok: true });
});

app.post('/api/trips', requireAuth, async (req, res) => {
  const state = await getState();
  const b = req.body;
  const required = ['companyId', 'tripNumber', 'kbo', 'companyName', 'plate', 'driverCard', 'startLat', 'startLng'];
  for (const f of required) if (b[f] === undefined || b[f] === '') return res.status(400).json({ error: 'حقل مطلوب: ' + f });
  const trip = { id: crypto.randomUUID(), status: 'BOOKED', createdAt: new Date().toISOString(), ...b };
  state.trips.push(trip);
  addAudit(state, 'create', 'trip', trip.id);
  await saveState(state);
  res.status(201).json(trip);
});

app.post('/api/trips/:id/:action', requireAuth, async (req, res) => {
  try {
    const state = await getState();
    const trip = state.trips.find(x => x.id === req.params.id);
    const action = req.params.action;
    if (!trip) return res.status(404).json({ error: 'الرحلة غير موجودة' });
    if (!['start', 'stop', 'cancel'].includes(action)) return res.status(404).json({ error: 'Not found' });

    if (action === 'cancel') {
      if (['STARTED', 'COMPLETED'].includes(trip.status)) return res.status(400).json({ error: 'لا يمكن إلغاء رحلة بدأت' });
      trip.status = req.body.reason === 'NO_SHOW' ? 'NO_SHOW' : 'CANCELLED';
      trip.cancelReason = req.body.reason || 'OTHER';
      await saveState(state);
      return res.json(trip);
    }

    const status = action === 'start' ? 'vertrek' : 'aankomst';
    if (action === 'start' && trip.status !== 'BOOKED') return res.status(400).json({ error: 'الرحلة ليست جاهزة للبدء' });
    if (action === 'stop' && trip.status !== 'STARTED') return res.status(400).json({ error: 'يجب إرسال START أولاً' });

    if (action === 'start') {
      trip.startedAt = req.body.startedAt || new Date().toISOString();
      trip.startLat = req.body.startLat ?? trip.startLat;
      trip.startLng = req.body.startLng ?? trip.startLng;
    } else {
      trip.endedAt = req.body.endedAt || new Date().toISOString();
      trip.endLat = req.body.endLat;
      trip.endLng = req.body.endLng;
      trip.distanceKm = req.body.distanceKm;
      trip.price = req.body.price;
      for (const f of ['endLat', 'endLng', 'distanceKm', 'price']) {
        if (trip[f] === undefined || trip[f] === '') return res.status(400).json({ error: 'حقل وصول مطلوب: ' + f });
      }
    }

    const company = state.companies.find(x => x.id === trip.companyId);
    const environment = req.body.environment || 'test';
    const payload = buildChironPayload(trip, status);
    const accessToken = await getAccessToken(company, environment);
    const r = await axios.post(ENVIRONMENTS[environment].trip, payload, {
      headers: { Authorization: 'Bearer ' + accessToken, 'Content-Type': 'application/json' }, timeout: 20000
    });
    const message = {
      id: crypto.randomUUID(), tripId: trip.id, environment, status, request: payload,
      response: r.data, at: new Date().toISOString(), ok: !r.data?.fouten?.length
    };
    state.messages.push(message);
    trip.status = action === 'start' ? 'STARTED' : 'COMPLETED';
    addAudit(state, 'chiron_' + status, 'trip', trip.id);
    await saveState(state);
    res.json({ ok: message.ok, chiron: r.data, trip });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.response?.data || e.message });
  }
});

app.use(express.static(path.join(__dirname, '../../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../../frontend/index.html')));

(async () => {
  if (DB) {
    await DB.query(fs.readFileSync(path.join(__dirname, '../migrations/001_init.sql'), 'utf8'));
  } else if (!fs.existsSync(FALLBACK_FILE)) {
    fs.writeFileSync(FALLBACK_FILE, JSON.stringify(blankState(), null, 2));
  }
  app.listen(PORT, () => console.log('Golden Taxi Chiron running on port ' + PORT));
})().catch(e => { console.error(e); process.exit(1); });
