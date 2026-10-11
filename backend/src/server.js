require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DASHBOARD_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET) {
  console.error('JWT_SECRET missing in .env');
  process.exit(1);
}

if (!DASHBOARD_PASSWORD) {
  console.error('ADMIN_PASSWORD missing in .env');
  process.exit(1);
}

const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const DATA_FILE = path.join(__dirname, '..', 'data.json');

let db = {
  companies: [],
  drivers: [],
  vehicles: [],
  customers: [],
  trips: [],
  invoices: [],
  messages: []
};

function loadDb(){
  try{
    if(fs.existsSync(DATA_FILE)){
      db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  }catch(err){
    console.error('Error loading data.json:', err.message);
  }
}

function saveDb(){
  try{
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  }catch(err){
    console.error('Error saving data.json:', err.message);
  }
}

loadDb();

function auth(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if(!token){
    return res.status(401).json({ error: 'غير مسجل الدخول' });
  }

  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch(err){
    return res.status(401).json({ error: 'جلسة منتهية، سجل الدخول مجددًا' });
  }
}

function findCompany(companyId){
  return db.companies.find(function(c){
    return c.id === companyId;
  });
}

function getChironConfig(company, environment){
  if(!company || !company.chiron || !company.chiron[environment]){
    return null;
  }

  const config = company.chiron[environment];

  if(!config.clientId || !config.clientSecret){
    return null;
  }

  return config;
}

async function getChironToken(company, environment){
  const config = getChironConfig(company, environment);

  if(!config){
    throw new Error('بيانات Chiron غير مكتملة لهذه الشركة');
  }

  const tokenUrl =
    environment === 'production'
      ? 'https://mow.api.vlaanderen.be/oauth/token'
      : 'https://mow-acc.api.vlaanderen.be/oauth/token';

  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');
  params.append('client_id', config.clientId);
  params.append('client_secret', config.clientSecret);

  const response = await axios.post(tokenUrl, params, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    timeout: 15000
  });

  return response.data.access_token;
}

function utcIso(date){
  return new Date(date).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function buildStartMessage(trip){
  return {
    status: 'vertrek',
    rit: {
      ritnummer: trip.tripNumber,
      taxibedrijf: {
        aanbieder: {
          registratie: trip.kbo,
          naam: trip.companyName
        }
      }
    },
    voertuig: {
      nummerplaat: trip.plate
    },
    uitvoerder: {
      bestuurderspasnummer: trip.driverCard
    },
    vertrektijdstip: utcIso(trip.startedAt),
    vertrekpunt: {
      lengtegraad: Number(trip.startLng),
      breedtegraad: Number(trip.startLat)
    },
    kostprijs: {
      waarde: 0
    },
    broncreatiedatum: utcIso(new Date())
  };
}

function buildStopMessage(trip){
  return {
    status: 'aankomst',
    rit: {
      ritnummer: trip.tripNumber,
      taxibedrijf: {
        aanbieder: {
          registratie: trip.kbo,
          naam: trip.companyName
        }
      }
    },
    voertuig: {
      nummerplaat: trip.plate
    },
    uitvoerder: {
      bestuurderspasnummer: trip.driverCard
    },
    vertrektijdstip: utcIso(trip.startedAt),
    vertrekpunt: {
      lengtegraad: Number(trip.startLng),
      breedtegraad: Number(trip.startLat)
    },
    aankomsttijdstip: utcIso(trip.endedAt),
    aankomstpunt: {
      lengtegraad: Number(trip.endLng),
      breedtegraad: Number(trip.endLat)
    },
    afstand: {
      waarde: Number(trip.distanceKm)
    },
    kostprijs: {
      waarde: Number(trip.price)
    },
    broncreatiedatum: utcIso(new Date())
  };
}

async function sendToChiron(company, environment, message, tripId){
  let ok = false;
  let response = null;

  try{
    const accessToken = await getChironToken(company, environment);

    const apiUrl =
      environment === 'production'
        ? 'https://mow.api.vlaanderen.be/chiron/taxirit'
        : 'https://mow-acc.api.vlaanderen.be/chiron/taxirit';

    const apiResponse = await axios.post(apiUrl, message, {
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Content-Type': 'application/json'
      },
      timeout: 20000
    });

    ok = true;
    response = apiResponse.data;
  }catch(err){
    response = err.response ? err.response.data : { error: err.message };
  }

  db.messages.push({
    id: Date.now().toString() + Math.random().toString(16).slice(2),
    tripId: tripId,
    environment: environment,
    status: message.status,
    ok: ok,
    date: new Date().toISOString(),
    response: response
  });

  saveDb();

  return ok;
}

app.use(express.static(FRONTEND_DIR));

app.get('/', function(req, res){
  res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
});

app.get('/api-status', function(req, res){
  res.json({
    status: 'OK',
    message: 'Golden Taxi Chiron server is running'
  });
});

app.post('/api/login', function(req, res){
  const password = req.body.password;

  if(!password || password !== DASHBOARD_PASSWORD){
    return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
  }

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });

  res.json({ token: token });
});

app.get('/api/companies', auth, function(req, res){
  res.json(db.companies);
});

app.post('/api/companies', auth, function(req, res){
  const { name, kbo, btw, address, email, phone } = req.body;

  if(!name || !kbo){
    return res.status(400).json({ error: 'اسم الشركة و KBO مطلوبان' });
  }

  const company = {
    id: Date.now().toString(),
    name: name,
    kbo: kbo,
    btw: btw || '',
    address: address || '',
    email: email || '',
    phone: phone || '',
    chiron: {
      test: { clientId: '', clientSecret: '', configured: false },
      production: { clientId: '', clientSecret: '', configured: false }
    }
  };

  db.companies.push(company);
  saveDb();

  res.json(company);
});

app.delete('/api/companies/:id', auth, function(req, res){
  db.companies = db.companies.filter(function(c){
    return c.id !== req.params.id;
  });

  saveDb();
  res.json({ ok: true });
});

app.put('/api/companies/:id/chiron', auth, function(req, res){
  const company = findCompany(req.params.id);

  if(!company){
    return res.status(404).json({ error: 'الشركة غير موجودة' });
  }

  const { environment, clientId, secret } = req.body;

  if(!['test', 'production'].includes(environment)){
    return res.status(400).json({ error: 'بيئة غير صحيحة' });
  }

  company.chiron[environment] = {
    clientId: clientId || '',
    clientSecret: secret || '',
    configured: Boolean(clientId && secret)
  };

  saveDb();

  res.json({ ok: true });
});

app.post('/api/chiron/:id/hello', auth, async function(req, res){
  const company = findCompany(req.params.id);
  const environment = req.body.environment || 'test';

  try{
    await getChironToken(company, environment);
    res.json({ ok: true });
  }catch(err){
    res.json({ ok: false, error: err.message });
  }
});

app.get('/api/drivers', auth, function(req, res){
  res.json(db.drivers);
});

app.post('/api/drivers', auth, function(req, res){
  const driver = {
    id: Date.now().toString(),
    name: req.body.name || '',
    card: req.body.card || '',
    phone: req.body.phone || ''
  };

  db.drivers.push(driver);
  saveDb();

  res.json(driver);
});

app.delete('/api/drivers/:id', auth, function(req, res){
  db.drivers = db.drivers.filter(function(d){
    return d.id !== req.params.id;
  });

  saveDb();
  res.json({ ok: true });
});

app.get('/api/vehicles', auth, function(req, res){
  res.json(db.vehicles);
});

app.post('/api/vehicles', auth, function(req, res){
  const vehicle = {
    id: Date.now().toString(),
    brand: req.body.brand || '',
    model: req.body.model || '',
    plate: req.body.plate || ''
  };

  db.vehicles.push(vehicle);
  saveDb();

  res.json(vehicle);
});

app.delete('/api/vehicles/:id', auth, function(req, res){
  db.vehicles = db.vehicles.filter(function(v){
    return v.id !== req.params.id;
  });

  saveDb();
  res.json({ ok: true });
});

app.get('/api/customers', auth, function(req, res){
  res.json(db.customers);
});

app.post('/api/customers', auth, function(req, res){
  const customer = {
    id: Date.now().toString(),
    name: req.body.name || '',
    phone: req.body.phone || ''
  };

  db.customers.push(customer);
  saveDb();

  res.json(customer);
});

app.delete('/api/customers/:id', auth, function(req, res){
  db.customers = db.customers.filter(function(c){
    return c.id !== req.params.id;
  });

  saveDb();
  res.json({ ok: true });
});

app.get('/api/trips', auth, function(req, res){
  res.json(db.trips);
});

app.post('/api/trips', auth, function(req, res){
  const {
    companyId,
    environment,
    tripNumber,
    kbo,
    companyName,
    plate,
    driverCard,
    passenger,
    payment,
    startAddress,
    startLat,
    startLng
  } = req.body;

  if(!companyId){
    return res.status(400).json({ error: 'اختر الشركة' });
  }

  if(!['test', 'production'].includes(environment)){
    return res.status(400).json({ error: 'اختر البيئة: TEST أو Production' });
  }

  if(!tripNumber){
    return res.status(400).json({ error: 'أدخل رقم الرحلة' });
  }

  if(!plate){
    return res.status(400).json({ error: 'أدخل رقم لوحة السيارة' });
  }

  if(!driverCard){
    return res.status(400).json({ error: 'أدخل رقم بطاقة السائق' });
  }

  if(isNaN(Number(startLat)) || isNaN(Number(startLng))){
    return res.status(400).json({ error: 'إحداثيات البداية مطلوبة' });
  }

  const trip = {
    id: Date.now().toString(),
    companyId: companyId,
    environment: environment,
    tripNumber: tripNumber,
    kbo: kbo || '',
    companyName: companyName || '',
    plate: plate,
    driverCard: driverCard,
    passenger: passenger || '',
    payment: payment || '',
    startAddress: startAddress || '',
    startLat: Number(startLat),
    startLng: Number(startLng),
    endAddress: '',
    endLat: null,
    endLng: null,
    distanceKm: null,
    price: null,
    status: 'BOOKED',
    startedAt: null,
    endedAt: null,
    createdAt: new Date().toISOString()
  };

  db.trips.push(trip);
  saveDb();

  res.json(trip);
});

app.post('/api/trips/:id/start', auth, async function(req, res){
  const trip = db.trips.find(function(t){
    return t.id === req.params.id;
  });

  if(!trip){
    return res.status(404).json({ error: 'الرحلة غير موجودة' });
  }

  if(trip.status !== 'BOOKED'){
    return res.status(400).json({ error: 'الرحلة بدأت مسبقًا' });
  }

  const company = findCompany(trip.companyId);

  if(!company){
    return res.status(400).json({ error: 'الشركة غير موجودة' });
  }

  trip.startedAt = new Date().toISOString();
  trip.status = 'STARTED';

  const message = buildStartMessage(trip);
  const ok = await sendToChiron(company, trip.environment, message, trip.id);

  saveDb();

  if(!ok){
    return res.status(400).json({
      ok: false,
      error: 'فشل إرسال START إلى Chiron',
      details: db.messages[db.messages.length - 1].response
    });
  }

  res.json({ ok: true, trip: trip });
});

app.post('/api/trips/:id/stop', auth, async function(req, res){
  const trip = db.trips.find(function(t){
    return t.id === req.params.id;
  });

  if(!trip){
    return res.status(404).json({ error: 'الرحلة غير موجودة' });
  }

  if(trip.status !== 'STARTED'){
    return res.status(400).json({ error: 'الرحلة لم تبدأ أو انتهت مسبقًا' });
  }

  const endLat = Number(req.body.endLat);
  const endLng = Number(req.body.endLng);
  const distanceKm = Number(req.body.distanceKm);
  const price = Number(req.body.price);

  if(isNaN(endLat) || isNaN(endLng)){
    return res.status(400).json({ error: 'إحداثيات الوصول مطلوبة' });
  }

  if(isNaN(distanceKm) || distanceKm <= 0){
    return res.status(400).json({ error: 'المسافة غير صحيحة' });
  }

  if(isNaN(price) || price < 0){
    return res.status(400).json({ error: 'السعر غير صحيح' });
  }

  const company = findCompany(trip.companyId);

  if(!company){
    return res.status(400).json({ error: 'الشركة غير موجودة' });
  }

  trip.endLat = endLat;
  trip.endLng = endLng;
  trip.distanceKm = distanceKm;
  trip.price = price;
  trip.endedAt = new Date().toISOString();
  trip.status = 'COMPLETED';

  const message = buildStopMessage(trip);
  const ok = await sendToChiron(company, trip.environment, message, trip.id);

  saveDb();

  if(!ok){
    return res.status(400).json({
      ok: false,
      error: 'فشل إرسال STOP إلى Chiron',
      details: db.messages[db.messages.length - 1].response
    });
  }

  res.json({ ok: true, trip: trip });
});

app.get('/api/invoices', auth, function(req, res){
  res.json(db.invoices);
});

app.post('/api/invoices', auth, function(req, res){
  const invoice = req.body;

  if(!invoice.tripId){
    return res.status(400).json({ error: 'tripId مطلوب' });
  }

  invoice.id = Date.now().toString();
  invoice.date = invoice.date || new Date().toISOString();

  db.invoices.push(invoice);
  saveDb();

  res.json(invoice);
});

app.put('/api/invoices/:id', auth, function(req, res){
  const invoice = db.invoices.find(function(i){
    return i.id === req.params.id;
  });

  if(!invoice){
    return res.status(404).json({ error: 'الفاتورة غير موجودة' });
  }

  if(req.body.status){
    invoice.status = req.body.status;
  }

  saveDb();

  res.json(invoice);
});

app.get('/api/messages', auth, function(req, res){
  res.json(db.messages);
});

app.use(function(req, res){
  res.status(404).json({ error: 'المسار غير موجود' });
});

app.listen(PORT, function(){
  console.log('Golden Taxi Chiron running on port ' + PORT);
});
