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

const DB = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    })
  : null;

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

const blankState = () => ({
  companies: [],
  drivers: [],
  vehicles: [],
  customers: [],
  trips: [],
  invoices: [],
  messages: [],
  audit: []
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
  } catch {
    return '';
  }
}

async function getState() {
  if (!DB) {
    try {
      return JSON.parse(fs.readFileSync(FALLBACK_FILE, 'utf8'));
    } catch {
      return blankState();
    }
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
    `INSERT INTO golden_state (id, data)
     VALUES (1, $1)
     ON CONFLICT (id)
     DO UPDATE SET data = $1, updated_at = now()`,
    [state]
  );
}

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

function addAudit(state, action, type, itemId) {
  state.audit.push({
    id: crypto.randomUUID(),
    action,
    type,
    itemId,
    at: new Date().toISOString()
  });
}

async function getAccessToken(company, environment) {
  const credentials = company.chiron?.[environment];

  if (!credentials?.clientId || !credentials?.secret) {
    throw new Error('Client ID أو Client Secret غير موجودين لهذه البيئة');
  }

  const basic = Buffer.from(credentials.clientId + ':' + decryptValue(credentials.secret)).toString('base64');

  const response = await axios.post(
    ENVIRONMENTS[environment].oauth,
    'grant_type=client_credentials',
    {
      headers: {
        Authorization: 'Basic ' + basic,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 15000
    }
  );

  return response.data.access_token;
}

function buildChironPayload(trip, status) {
  const payload = {
    taxibedrijf: {
      aanbieder: {
        registratie: trip.kbo,
        naam: trip.companyName
      }
    },
    voertuig: {
      nummerplaat: trip.plate
    },
    uitvoerder: {
      bestuurderspasnummer: trip.driverCard
    },
    vertrektijdstip: trip.startedAt,
    vertrekpunt: {
      lengtegraad: Number(trip.startLng),
      breedtegraad: Number(trip.startLat)
    }
  };

  if (status === 'aankomst') {
    payload.aankomsttijdstip = trip.endedAt;
    payload.aankomstpunt = {
      lengtegraad: Number(trip.endLng),
      breedtegraad: Number(trip.endLat)
    };
    payload.afstand = {
      waarde: Number(trip.distanceKm)
    };
    payload.kostprijs = {
      waarde: Number(trip.price)
    };
  }

  return {
    status,
    ritnummer: trip.tripNumber,
    rit: payload,
    broncreatiedatum: new Date().toISOString()
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, database: Boolean(DB) });
});

app.post('/api/login', (req, res) => {
  const password = String(req.body.password || '');
  const expected = process.env.ADMIN_PASSWORD || '';
  const hash = process.env.ADMIN_PASSWORD_HASH || '';

  let ok = false;

  if (expected && password === expected) {
    ok = true;
  } else if (hash && bcrypt.compareSync(password, hash)) {
    ok = true;
  }

  if (!ok) {
    return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
  }

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

app.get('/api/:type', requireAuth, async (req, res) => {
  const allowed = ['companies', 'drivers', 'vehicles', 'customers', 'trips', 'invoices', 'messages', 'audit'];

  if (!allowed.includes(req.params.type)) {
    return res.status(404).json({ error: 'Not found' });
  }

  const state = await getState();
  let items = state[req.params.type];

  if (req.params.type === 'companies') {
    items = items.map(company => ({
      ...company,
      chiron: {
        test: {
          clientId: company.chiron?.test?.clientId || '',
          configured: Boolean(company.chiron?.test?.secret)
        },
        production: {
          clientId: company.chiron?.production?.clientId || '',
          configured: Boolean(company.chiron?.production?.secret)
        }
      }
    }));
  }

  res.json(items);
});

app.post('/api/companies', requireAuth, async (req, res) => {
  const state = await getState();
  const body = req.body;

  if (!body.name || !body.kbo) {
    return res.status(400).json({ error: 'اسم الشركة و KBO مطلوبان' });
  }

  const company = {
    id: crypto.randomUUID(),
    name: body.name,
    kbo: body.kbo,
    address: body.address || '',
    email: body.email || '',
    phone: body.phone || '',
    chiron: {
      test: {
        clientId: body.testClientId || '',
        secret: encryptValue(body.testSecret || '')
      },
      production: {
        clientId: body.productionClientId || '',
        secret: encryptValue(body.productionSecret || '')
      }
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
  const company = state.companies.find(item => item.id === req.params.id);
  const body = req.body;

  if (!company) {
    return res.status(404).json({ error: 'الشركة غير موجودة' });
  }

  if (!['test', 'production'].includes(body.environment)) {
    return res.status(400).json({ error: 'بيئة غير صحيحة' });
  }

  company.chiron[body.environment] = {
    clientId: body.clientId || '',
    secret: body.secret ? encryptValue(body.secret) : company.chiron[body.environment]?.secret || ''
  };

  addAudit(state, 'update_credentials', body.environment, company.id);
  await saveState(state);

  res.json({ ok: true });
});

app.post('/api/chiron/:companyId/hello', requireAuth, async (req, res) => {
  try {
    const state = await getState();
    const company = state.companies.find(item => item.id === req.params.companyId);
    const environment = req.body.environment || 'test';

    if (!company) {
      return res.status(404).json({ error: 'الشركة غير موجودة' });
    }

    if (environment !== 'test') {
      return res.status(400).json({ error: 'hello متاح في TEST فقط' });
    }

    const credentials = company.chiron.test;
    const basic = Buffer.from(credentials.clientId + ':' + decryptValue(credentials.secret)).toString('base64');

    const response = await axios.get(ENVIRONMENTS.test.hello, {
      headers: {
        Authorization: 'Basic ' + basic
      },
      timeout: 15000
    });

    res.json({ ok: true, response: response.data });
  } catch (error) {
    res.status(400).json({
      ok: false,
      error: error.response?.data || error.message
    });
  }
});

app.post('/api/trips', requireAuth, async (req, res) => {
  const state = await getState();
  const body = req.body;

  const required = [
    'companyId',
    'tripNumber',
    'kbo',
    'companyName',
    'plate',
    'driverCard',
    'startLat',
    'startLng'
  ];

  for (const field of required) {
    if (body[field] === undefined || body[field] === '') {
      return res.status(400).json({ error: 'حقل مطلوب: ' + field });
    }
  }

  const trip = {
    id: crypto.randomUUID(),
    status: 'BOOKED',
    createdAt: new Date().toISOString(),
    ...body
  };

  state.trips.push(trip);
  addAudit(state, 'create', 'trip', trip.id);
  await saveState(state);

  res.status(201).json(trip);
});

app.post('/api/trips/:id/:action', requireAuth, async (req, res) => {
  try {
    const state = await getState();
    const trip = state.trips.find(item => item.id === req.params.id);
    const action = req.params.action;

    if (!trip) {
      return res.status(404).json({ error: 'الرحلة غير موجودة' });
    }

    if (!['start', 'stop', 'cancel'].includes(action)) {
      return res.status(404).json({ error: 'Not found' });
    }

    if (action === 'cancel') {
      if (['STARTED', 'COMPLETED'].includes(trip.status)) {
        return res.status(400).json({ error: 'لا يمكن إلغاء رحلة بدأت' });
      }

      trip.status = req.body.reason === 'NO_SHOW' ? 'NO_SHOW' : 'CANCELLED';
      trip.cancelReason = req.body.reason || 'OTHER';

      await saveState(state);
      return res.json(trip);
    }

    const status = action === 'start' ? 'vertrek' : 'aankomst';

    if (action === 'start' && trip.status !== 'BOOKED') {
      return res.status(400).json({ error: 'الرحلة ليست جاهزة للبدء' });
    }

    if (action === 'stop' && trip.status !== 'STARTED') {
      return res.status(400).json({ error: 'يجب إرسال START أولاً' });
    }

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

      const required = ['endLat', 'endLng', 'distanceKm', 'price'];

      for (const field of required) {
        if (trip[field] === undefined || trip[field] === '') {
          return res.status(400).json({ error: 'حقل وصول مطلوب: ' + field });
        }
      }
    }

    const company = state.companies.find(item => item.id === trip.companyId);
    const environment = req.body.environment || 'test';
    const payload = buildChironPayload(trip, status);
    const accessToken = await getAccessToken(company, environment);

    const response = await axios.post(ENVIRONMENTS[environment].trip, payload, {
      headers: {
        Authorization: 'Bearer ' + accessToken,
        'Content-Type': 'application/json'
      },
      timeout: 20000
    });

    const message = {
      id: crypto.randomUUID(),
      tripId: trip.id,
      environment,
      status,
      request: payload,
      response: response.data,
      at: new Date().toISOString(),
      ok: !response.data?.fouten?.length
    };

    state.messages.push(message);
    trip.status = action === 'start' ? 'STARTED' : 'COMPLETED';

    addAudit(state, 'chiron_' + status, 'trip', trip.id);
    await saveState(state);

    res.json({ ok: message.ok, chiron: response.data, trip });
  } catch (error) {
    res.status(400).json({
      ok: false,
      error: error.response?.data || error.message
    });
  }
});

app.use(express.static(path.join(__dirname, '../../frontend')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../../frontend/index.html'));
});

(async () => {
  if (DB) {
    const migration = fs.readFileSync(path.join(__dirname, '../migrations/001_init.sql'), 'utf8');
    await DB.query(migration);
  } else if (!fs.existsSync(FALLBACK_FILE)) {
    fs.writeFileSync(FALLBACK_FILE, JSON.stringify(blankState(), null, 2));
  }

  app.listen(PORT, () => {
    console.log('Golden Taxi Chiron running on port ' + PORT);
  });
})().catch(error => {
  console.error(error);
  process.exit(1);
});
