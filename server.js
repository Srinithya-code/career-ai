const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Groq = require('groq-sdk');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'careerai_default_secret';

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'job portal.html'));
});

/* ================================================================
   DATABASE
   ================================================================ */
const os = require('os');

const dbPath = path.join(os.tmpdir(), 'careerai.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS user_data (
    user_id TEXT NOT NULL,
    data_key TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, data_key),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const stmts = {
  findUserByEmail: db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE'),
  insertUser: db.prepare('INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)'),
  getData: db.prepare('SELECT data_json FROM user_data WHERE user_id = ? AND data_key = ?'),
  upsertData: db.prepare(`INSERT INTO user_data (user_id, data_key, data_json, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, data_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`),
};

/* ================================================================
   AUTH MIDDLEWARE
   ================================================================ */
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = decoded.userId;
    req.userName = decoded.name;
    req.userEmail = decoded.email;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* ================================================================
   AUTH ENDPOINTS
   ================================================================ */
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Valid email is required' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const existing = stmts.findUserByEmail.get(email);
  if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  stmts.insertUser.run(id, name.trim(), email.toLowerCase().trim(), hash);

  const token = jwt.sign({ userId: id, name: name.trim(), email: email.toLowerCase().trim() }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { name: name.trim(), email: email.toLowerCase().trim() } });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  const user = stmts.findUserByEmail.get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign({ userId: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { name: user.name, email: user.email } });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ name: req.userName, email: req.userEmail });
});

/* ================================================================
   DATA ENDPOINTS
   ================================================================ */
const VALID_KEYS = new Set(['profile', 'jobs', 'applied', 'saved', 'history', 'meta']);

app.get('/api/data/:key', (req, res) => {
  if (!VALID_KEYS.has(req.params.key)) return res.status(400).json({ error: 'Invalid data key' });
  const userId = req.headers['x-session-id'] || 'anonymous';
  const row = stmts.getData.get(userId, req.params.key);
  try {
    res.json({ data: row ? JSON.parse(row.data_json) : null });
  } catch (e) {
    res.json({ data: null });
  }
});

app.post('/api/data/:key', (req, res) => {
  if (!VALID_KEYS.has(req.params.key)) return res.status(400).json({ error: 'Invalid data key' });
  const userId = req.headers['x-session-id'] || 'anonymous';
  const json = JSON.stringify(req.body.data ?? req.body);
  stmts.upsertData.run(userId, req.params.key, json);
  res.json({ ok: true });
});

/* ================================================================
   JOB SEARCH CACHE — 30 minute TTL
   ================================================================ */
const jobCache = new Map();
const CACHE_TTL = 30 * 60 * 1000;

function getCached(key) {
  const entry = jobCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { jobCache.delete(key); return null; }
  return entry.data;
}

function setCache(key, data) {
  jobCache.set(key, { data, ts: Date.now() });
  if (jobCache.size > 200) {
    const oldest = jobCache.keys().next().value;
    jobCache.delete(oldest);
  }
}

/* ================================================================
   SKILL EXTRACTION FROM JOB DESCRIPTIONS
   ================================================================ */
const KNOWN_SKILLS = [
  'JavaScript','TypeScript','React','Angular','Vue.js','Node.js','Express','Python','Django','Flask',
  'Java','Spring Boot','Spring','Hibernate','C#','.NET','Go','Rust','Ruby','Rails','PHP','Laravel',
  'HTML','CSS','Sass','Tailwind CSS','Bootstrap','Redux','Webpack','GraphQL','REST API',
  'SQL','MySQL','PostgreSQL','MongoDB','Redis','Kafka','Elasticsearch',
  'Docker','Kubernetes','Jenkins','Terraform','Ansible','CI/CD','Git','Linux','Nginx',
  'AWS','Azure','GCP','Lambda','S3','EC2','CloudFormation','Serverless',
  'Machine Learning','Deep Learning','TensorFlow','PyTorch','Keras','Scikit-learn','NLP','Computer Vision','OpenCV','LLM',
  'Pandas','NumPy','Matplotlib','Jupyter','R','Statistics','Tableau','Power BI','Excel','Data Analysis',
  'Selenium','JUnit','TestNG','Cypress','Jest','Postman','JMeter','Appium','JIRA',
  'Figma','Adobe XD','Sketch','Wireframing','Prototyping',
  'Network Security','Penetration Testing','SIEM','Firewall','OWASP','Wireshark','Metasploit','Nmap','Cryptography',
  'Verilog','VHDL','RTL Design','FPGA','ASIC','DFT','STA','Physical Design','SystemVerilog','UVM','Cadence','Synopsys',
  'C','C++','ARM','RTOS','Microcontrollers','Arduino','Raspberry Pi','Embedded Linux','STM32','Firmware',
  'MQTT','ESP32','Sensors','IoT',
  'AutoCAD','SolidWorks','CATIA','ANSYS','CFD','FEA','CNC','GD&T','MATLAB','Simulink','Creo',
  'Revit','STAAD Pro','ETABS','Primavera','Surveying',
  'PLC','SCADA','Power Systems','Control Systems',
  'HYSYS','Aspen Plus',
  'PCR','Cell Culture','CRISPR','Bioinformatics','Genomics',
  'CRM','Salesforce','HubSpot','Zendesk','Freshdesk',
  'SEO','SEM','Google Ads','Google Analytics','Content Marketing','Email Marketing',
  'Recruitment','HRIS','Payroll','SAP HR','Workday',
  'Financial Modeling','Valuation','SAP FICO','Tally','QuickBooks','GST','Audit',
  'Supply Chain','Lean','Six Sigma','ERP','SAP',
  'React Native','Flutter','Swift','Kotlin','Android','iOS','Firebase',
  'Prometheus','Grafana','ArgoCD',
  'Spark','Hadoop','Airflow',
  'Communication','Problem Solving','Agile','Scrum',
  'TCL','Floorplanning','CTS','Power Planning','ECO','DRC','LVS','IR Drop',
  'ModelSim','QuestaSim','Xilinx Vivado','Xilinx ISE','Microwind',
  'Embedded C','Design Compiler','IC Compiler','ICC2','Genus','Innovus','Synthesis',
  'FastAPI','Next.js','Nuxt.js','Svelte','Deno','Bun',
];

const SKILLS_LOWER = KNOWN_SKILLS.map(s => ({
  original: s,
  re: new RegExp('\\b' + s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+') + '\\b', 'i')
}));

function extractSkillsFromDescription(desc) {
  if (!desc) return [];
  const found = new Set();
  for (const sk of SKILLS_LOWER) {
    if (sk.re.test(desc)) found.add(sk.original);
  }
  return Array.from(found);
}

/* ================================================================
   DOMAIN DETECTION & MATCHING ENGINE
   ================================================================ */
const DOMAIN_SKILL_MAP = {
  'Full Stack':['JavaScript','TypeScript','React','Node.js','Express','Django','Flask','MongoDB','PostgreSQL','REST API','Docker','Git','HTML','CSS'],
  'Frontend':['HTML','CSS','JavaScript','TypeScript','React','Angular','Vue.js','Redux','Webpack','Tailwind CSS','Bootstrap'],
  'Backend':['Node.js','Express','Django','Flask','Spring Boot','Java','Python','Go','C#','.NET','PostgreSQL','MySQL','MongoDB','Redis','REST API'],
  'Mobile':['React Native','Flutter','Swift','Kotlin','Android','iOS','Java','Firebase'],
  'Data Science':['Python','R','SQL','Pandas','NumPy','Scikit-learn','TensorFlow','Matplotlib','Jupyter','Statistics','Machine Learning','Tableau','Power BI'],
  'AI/ML':['Python','TensorFlow','PyTorch','Keras','Scikit-learn','NLP','Computer Vision','Deep Learning','Machine Learning','OpenCV','LLM'],
  'Cybersecurity':['Network Security','Penetration Testing','SIEM','Firewall','Cryptography','OWASP','Wireshark','Metasploit','Nmap'],
  'Cloud':['AWS','Azure','GCP','Docker','Kubernetes','Terraform','Lambda','S3','EC2','Serverless','CloudFormation'],
  'DevOps':['Docker','Kubernetes','Jenkins','Terraform','Ansible','Prometheus','Grafana','Linux','CI/CD','Nginx'],
  'Testing/QA':['Selenium','JUnit','TestNG','Cypress','Jest','Postman','JMeter','Appium','JIRA'],
  'UI/UX':['Figma','Adobe XD','Sketch','Wireframing','Prototyping'],
  'VLSI/ECE':['Verilog','VHDL','RTL Design','FPGA','ASIC','DFT','STA','Physical Design','SystemVerilog','UVM','Cadence','Synopsys'],
  'Embedded':['C','C++','ARM','RTOS','Microcontrollers','Arduino','Raspberry Pi','Embedded Linux','STM32','Firmware'],
  'IoT':['MQTT','Arduino','Raspberry Pi','ESP32','Sensors','Python','C'],
  'Electrical':['Power Systems','Control Systems','PLC','SCADA','AutoCAD','MATLAB','Simulink'],
  'Mechanical':['AutoCAD','SolidWorks','CATIA','ANSYS','CFD','FEA','CNC','GD&T','MATLAB','Creo'],
  'Civil':['AutoCAD','Revit','STAAD Pro','ETABS','Primavera','Surveying'],
  'Biotechnology':['PCR','Cell Culture','CRISPR','Bioinformatics','Genomics','Python','R'],
  'Marketing':['SEO','SEM','Google Ads','Content Marketing','Google Analytics','HubSpot','Email Marketing'],
  'HR':['Recruitment','HRIS','Payroll','SAP HR','Workday'],
  'Finance':['Financial Modeling','Valuation','Excel','SAP FICO','Tally'],
  'Operations':['Supply Chain','Lean','Six Sigma','ERP','SAP'],
  'Research':['Python','R','MATLAB','Statistics','Data Analysis'],
};

function detectDomain(skills) {
  const userLower = new Set(skills.map(s => s.toLowerCase()));
  let best = 'General', bestScore = 0;
  for (const [domain, domSkills] of Object.entries(DOMAIN_SKILL_MAP)) {
    const matched = domSkills.filter(s => userLower.has(s.toLowerCase())).length;
    if (matched > bestScore) { bestScore = matched; best = domain; }
  }
  return best;
}

/* ================================================================
   EXPERIENCE LEVEL MATCHING
   ================================================================ */
const EXP_LEVELS = {
  'Fresher': [0, 0.5],
  '0-1 Years': [0, 1],
  '1-3 Years': [1, 3],
  '3-5 Years': [3, 5],
  '5+ Years': [5, 99],
};

function extractExpFromJobTitle(title) {
  const t = (title || '').toLowerCase();
  if (/\b(intern|trainee|apprentice|fresher|graduate)\b/i.test(t)) return [0, 1];
  if (/\b(junior|jr|entry.?level|associate)\b/i.test(t)) return [0, 2];
  if (/\b(senior|sr|lead|principal|staff)\b/i.test(t)) return [4, 99];
  if (/\b(manager|director|head|vp)\b/i.test(t)) return [6, 99];
  return null;
}

function experienceMatches(candidateYears, jobTitle, jobExpText) {
  if (candidateYears === null || candidateYears === undefined) return true;

  const jobRange = extractExpFromJobTitle(jobTitle);
  if (jobRange) {
    if (candidateYears < jobRange[0] - 1) return false;
    if (jobRange[1] < 99 && candidateYears > jobRange[1] + 3) return false;
  }

  if (jobExpText) {
    const m = jobExpText.match(/(\d+)\s*[-–—to]+\s*(\d+)/);
    if (m) {
      const min = parseInt(m[1]), max = parseInt(m[2]);
      if (candidateYears < min - 1 || candidateYears > max + 3) return false;
    }
    const m2 = jobExpText.match(/(?:at[- ]?least|minimum|min\.?)\s*(\d+)\s*(?:\+?\s*)?years?/i);
    const m3 = !m2 ? jobExpText.match(/(\d+)\+?\s*years?/i) : null;
    const reqMatch = m2 || m3;
    if (reqMatch && !m) {
      const req = parseInt(reqMatch[1]);
      if (candidateYears < req - 1) return false;
    }
  }
  return true;
}

/* ================================================================
   ROLE TITLE SIMILARITY — fuzzy word-overlap matching
   ================================================================ */
const ROLE_CORE_WORDS = {
  'rtl design engineer': ['rtl','design'],
  'asic design engineer': ['asic','design'],
  'asic verification engineer': ['asic','verification'],
  'fpga engineer': ['fpga'],
  'physical design engineer': ['physical','design'],
  'pd engineer': ['physical','design'],
  'physical implementation engineer': ['physical','implementation'],
  'backend physical design engineer': ['physical','design','backend'],
  'asic physical design engineer': ['physical','design','asic'],
  'vlsi physical design engineer': ['physical','design','vlsi'],
  'physical design ic engineer': ['physical','design'],
  'place and route engineer': ['place','route','apr'],
  'floorplan engineer': ['floorplan','physical'],
  'dft engineer': ['dft'],
  'sta engineer': ['sta','timing'],
  'timing engineer': ['timing','sta'],
  'layout engineer': ['layout'],
  'design verification engineer': ['verification','dv'],
  'analog design engineer': ['analog'],
  'digital design engineer': ['digital','design'],
  'verification engineer': ['verification','dv'],
  'react developer': ['react'],
  'angular developer': ['angular'],
  'vue developer': ['vue'],
  'node.js developer': ['node','nodejs'],
  'python developer': ['python','developer'],
  'java developer': ['java','developer'],
  'android developer': ['android'],
  'ios developer': ['ios','swift'],
  'flutter developer': ['flutter'],
  'etl developer': ['etl','data'],
  'data pipeline engineer': ['data','pipeline'],
  'automation tester': ['automation','test','qa'],
  'test automation engineer': ['automation','test'],
};

function getAliasesForRole(role) {
  if (ROLE_ALIASES[role]) return ROLE_ALIASES[role];
  const rl = role.toLowerCase();
  for (const [key, vals] of Object.entries(ROLE_ALIASES)) {
    const kl = key.toLowerCase();
    if (rl.includes(kl) || kl.includes(rl)) return vals;
  }
  const generic = new Set(['engineer','developer','analyst','designer','lead','senior','junior','staff','specialist','consultant','architect','manager','associate','intern']);
  const rWords = rl.split(/[\s/\-]+/).filter(w => w.length > 2 && !generic.has(w));
  if (rWords.length === 0) return null;
  let bestVals = null, bestScore = 0;
  for (const [key, vals] of Object.entries(ROLE_ALIASES)) {
    const kWords = key.toLowerCase().split(/[\s/\-]+/).filter(w => w.length > 2 && !generic.has(w));
    if (kWords.length === 0) continue;
    const overlap = rWords.filter(w => kWords.some(kw => kw === w || kw.includes(w) || w.includes(kw))).length;
    const score = overlap / Math.max(rWords.length, kWords.length);
    if (score > bestScore && score >= 0.4) { bestScore = score; bestVals = vals; }
  }
  return bestVals;
}

function roleTitleSimilarity(jobTitle, preferredRole) {
  if (!preferredRole || preferredRole === 'Other') return 100;
  const titleLower = jobTitle.toLowerCase();
  const roleLower = preferredRole.toLowerCase();

  if (titleLower.includes(roleLower)) return 100;

  const aliases = getAliasesForRole(preferredRole);
  let best = 0;

  if (aliases) {
    for (const alias of aliases) {
      if (alias.length < 4) continue;
      if (titleLower.includes(alias)) {
        const ratio = alias.length / Math.max(titleLower.length, 1);
        best = Math.max(best, Math.min(60 + Math.round(ratio * 40), 95));
      }
    }
  }

  const coreWords = ROLE_CORE_WORDS[roleLower];
  if (coreWords) {
    const hits = coreWords.filter(w => titleLower.includes(w));
    const primaryHit = coreWords.length > 0 && titleLower.includes(coreWords[0]);
    if (primaryHit && hits.length >= Math.ceil(coreWords.length / 2)) {
      const sim = Math.min(60 + Math.round((hits.length / coreWords.length) * 35), 95);
      if (sim > best) best = sim;
    }
  }

  if (best === 0) {
    const genericTitles = new Set(['engineer','developer','analyst','manager','designer','consultant','specialist','architect','lead','tester','coordinator','executive','officer','administrator','associate','intern','trainee']);
    const skipWords = new Set(['and','the','for','with','junior','senior','lead','sr','jr','staff','principal','intern','associate','mid','entry','level','in','at','of','or','to','a','an','is','as','by','on','from']);
    const roleWords = roleLower.split(/[\s/\-]+/).filter(w => w.length > 2 && !skipWords.has(w));
    const specificRoleWords = roleWords.filter(w => !genericTitles.has(w));
    const titleWords = titleLower.split(/[\s/\-,()]+/);

    const sigTitleWords = titleWords.filter(tw => tw.length > 2);
    if (specificRoleWords.length > 0) {
      const hits = specificRoleWords.filter(w => sigTitleWords.some(tw => tw.includes(w) || (w.length > 3 && w.includes(tw) && tw.length > 3)));
      if (hits.length > 0) {
        best = Math.round((hits.length / specificRoleWords.length) * 80);
      }
    } else if (roleWords.length > 0) {
      const hits = roleWords.filter(w => sigTitleWords.some(tw => tw === w));
      best = hits.length === roleWords.length ? 40 : 0;
    }
  }

  return best;
}

/* ================================================================
   JOB VALIDATION — reject incomplete/suspicious listings
   ================================================================ */
function validateJobData(job) {
  if (!job.company || job.company.trim().length < 2) return false;
  if (!job.title || job.title.trim().length < 3) return false;
  if (!job.applyLink) return false;
  try { new URL(job.applyLink); } catch { return false; }
  const t = job.title.toLowerCase();
  if (/\b(earn money|work from home.*guaranteed|mlm|commission only|registration fee|pay to apply)\b/i.test(t + ' ' + (job.description || ''))) return false;
  return true;
}

/* ================================================================
   SCORING ENGINE — FINAL
   Confirmed Roles 50% | Title Match 30% | JD Skills 10% | Experience 5% | Domain 5%

   HARD GATES (all must pass):
   1. Title similarity >= 60% against at least one confirmed role
   2. Candidate domain == Job domain (mandatory domain restriction)
   3. Experience must match
   ================================================================ */
function scoreJob(profile, job) {
  const preferredRole = profile.preferredRole || '';
  const selectedRoles = profile.selectedRoles || (preferredRole ? [preferredRole] : []);
  const hasConfirmedRoles = selectedRoles.length > 0 && !selectedRoles.includes('Other');
  const userSkills = new Set((profile.skills || []).map(s => s.toLowerCase()));
  const jobSkills = (job.skills || []).map(s => s.toLowerCase());

  /* ---- GATE 1: title must match a confirmed role (>= 25%) ---- */
  let bestTitleSim = 0;
  let matchedRole = '';
  if (hasConfirmedRoles) {
    for (const role of selectedRoles) {
      const sim = roleTitleSimilarity(job.title, role);
      if (sim > bestTitleSim) { bestTitleSim = sim; matchedRole = role; }
    }
    if (bestTitleSim < 25) return null;
  } else if (preferredRole && preferredRole !== 'Other') {
    bestTitleSim = roleTitleSimilarity(job.title, preferredRole);
    matchedRole = preferredRole;
    if (bestTitleSim < 25) return null;
  } else {
    bestTitleSim = 100;
  }

  /* ---- GATE 2: domain must match (skipped if title match is strong) ---- */
  const candidateDomain = profile.primaryDomain || detectDomain(profile.skills || []);
  const jobDomain = detectDomain(job.skills.length > 0 ? job.skills : [job.title]);
  if (bestTitleSim < 60 && candidateDomain !== 'General' && jobDomain !== 'General' && candidateDomain !== jobDomain) {
    return null;
  }

  /* ---- GATE 3: experience must match ---- */
  const candidateExp = profile.experienceYears ?? null;
  const expText = [job.employmentType, job.experienceRequired, job.description].filter(Boolean).join(' ');
  if (!experienceMatches(candidateExp, job.title, expText)) return null;

  /* ---- 1. User Confirmed Roles Match (50%) ---- */
  let confirmedRolePct = 0;
  if (hasConfirmedRoles) {
    const titleLower = job.title.toLowerCase();
    if (selectedRoles.some(r => titleLower.includes(r.toLowerCase()))) {
      confirmedRolePct = 100;
    } else if (bestTitleSim >= 80) {
      confirmedRolePct = 80;
    } else if (bestTitleSim >= 60) {
      confirmedRolePct = 60;
    } else if (bestTitleSim >= 40) {
      confirmedRolePct = 40;
    } else if (bestTitleSim >= 25) {
      confirmedRolePct = 25;
    }
  } else {
    confirmedRolePct = 50;
  }

  /* ---- 2. Job Title Match (30%) ---- */
  const titlePct = bestTitleSim;

  /* ---- 3. JD Skills Match (10%) ---- */
  const matched = jobSkills.filter(s => userSkills.has(s));
  const missing = jobSkills.filter(s => !userSkills.has(s));
  const jdSkillPct = jobSkills.length > 0 ? (matched.length / jobSkills.length) * 100 : 0;

  /* ---- 4. Experience Match (5%) ---- */
  let expMatchPct = 100;
  if (candidateExp !== null) {
    const jobRange = extractExpFromJobTitle(job.title);
    if (jobRange) {
      const mid = (jobRange[0] + Math.min(jobRange[1], 10)) / 2;
      const diff = Math.abs(candidateExp - mid);
      expMatchPct = Math.max(0, 100 - diff * 20);
    }
  }

  /* ---- 5. Projects/Domain Match (5%) ---- */
  let projDomainPct = candidateDomain === jobDomain ? 100 : 0;
  if (profile.projects && profile.projects.length > 0 && projDomainPct < 100) {
    const projTech = new Set(profile.projects.flatMap(p => (p.tech || '').split(/[,;]/).map(t => t.trim().toLowerCase())).filter(Boolean));
    const projOverlap = jobSkills.filter(s => projTech.has(s));
    const pct = jobSkills.length > 0 ? (projOverlap.length / jobSkills.length) * 100 : 0;
    if (pct > projDomainPct) projDomainPct = pct;
  }

  /* ---- FINAL SCORE ---- */
  let score = (0.50 * confirmedRolePct) + (0.30 * titlePct) + (0.10 * jdSkillPct) + (0.05 * expMatchPct) + (0.05 * projDomainPct);
  score = Math.round(Math.min(score, 100));

  if (score < 20) return null;

  return {
    score,
    titleMatchPct: Math.round(titlePct),
    skillMatchPct: Math.round(jdSkillPct),
    confirmedRolePct: Math.round(confirmedRolePct),
    experienceMatchPct: Math.round(expMatchPct),
    projectMatchPct: Math.round(projDomainPct),
    domainMatchPct: Math.round(projDomainPct),
    matchedSkills: matched.map(s => job.skills.find(js => js.toLowerCase() === s) || s),
    missingSkills: missing.map(s => job.skills.find(js => js.toLowerCase() === s) || s),
    matchedRole,
    domain: jobDomain
  };
}

/* ================================================================
   PREFERRED ROLE MAPPING — loose alias matching via includes()
   ================================================================ */
const ROLE_ALIASES = {
  'Data Analyst': ['data analyst','business analyst','bi analyst','reporting analyst','analytics associate','sql analyst','product analyst','data analytics','mis analyst','mis executive','analytics intern','junior analyst','analytics analyst'],
  'Data Scientist': ['data scientist','applied scientist','research scientist','quantitative analyst','data science','ml researcher','statistical analyst'],
  'AI/ML Engineer': ['ai engineer','ml engineer','machine learning','deep learning','nlp engineer','computer vision','ai developer','ai researcher','mlops','ai/ml','artificial intelligence'],
  'Software Developer': ['software developer','software engineer','application developer','programmer','sde','associate software','junior software','software development'],
  'Backend Developer': ['backend','back-end','server-side','api developer','node.js developer','python developer','java developer','go developer','.net developer','django developer','spring boot developer'],
  'Frontend Developer': ['frontend','front-end','ui developer','react developer','angular developer','vue developer','javascript developer','web developer','ui engineer'],
  'Full Stack Developer': ['full stack','full-stack','fullstack','mern','mean','software engineer','software developer','web developer','web application developer','backend developer','frontend developer'],
  'Cloud Engineer': ['cloud engineer','cloud architect','aws engineer','azure engineer','gcp engineer','cloud devops','cloud infrastructure','cloud solutions','cloud consultant'],
  'DevOps Engineer': ['devops','site reliability','sre','platform engineer','infrastructure engineer','release engineer','build engineer','ci/cd engineer'],
  'Cybersecurity Analyst': ['cybersecurity','security analyst','information security','soc analyst','security engineer','penetration test','ethical hack','threat analyst','security consultant'],
  'VLSI Engineer': ['vlsi','rtl design','physical design','dft engineer','verification engineer','asic design','asic verification','fpga engineer','chip design','sta engineer','layout engineer','analog design engineer','digital design engineer','semiconductor','silicon','digital asic','design verification'],
  'Digital ASIC': ['digital asic','asic design','asic verification','asic engineer','digital design','rtl design','vlsi','chip design','semiconductor','dft engineer'],
  'Physical Design': ['physical design','pd engineer','backend design','layout engineer','sta engineer','floorplan','placement','routing','vlsi','asic','chip design','semiconductor'],
  'RTL Design': ['rtl design','rtl engineer','digital design','asic design','vlsi','verilog','systemverilog','chip design'],
  'Design Verification': ['design verification','dv engineer','verification engineer','asic verification','uvm','functional verification','vlsi'],
  'ASIC Verification': ['asic verification','design verification','dv engineer','verification engineer','uvm','functional verification','vlsi'],
  'FPGA Design': ['fpga','fpga design','fpga engineer','fpga developer','digital design','vlsi','xilinx','vivado'],
  'Embedded Engineer': ['embedded','firmware','embedded systems','embedded c','rtos','iot engineer','microcontroller','embedded linux','stm32'],
  'Business Analyst': ['business analyst','business systems','functional analyst','requirements analyst','process analyst','product analyst','business consultant','domain analyst'],
  'UI/UX Designer': ['ui/ux','ux designer','ui designer','product designer','interaction designer','visual designer','ux researcher','user experience'],
  'Data Engineer': ['data engineer','etl developer','data pipeline','big data','data infrastructure','analytics engineer','data warehouse'],
  'QA Engineer': ['qa engineer','test engineer','sdet','quality analyst','automation tester','manual tester','qa analyst','test automation','performance tester'],
  'Mobile Developer': ['mobile developer','android developer','ios developer','react native','flutter developer','mobile app','swift developer','kotlin developer'],
  'Product Manager': ['product manager','associate product manager','technical product manager','product owner','program manager','product lead'],
  'Mechanical Engineer': ['mechanical engineer','design engineer','cad engineer','manufacturing engineer','production engineer','maintenance engineer','r&d engineer'],
  'Civil Engineer': ['civil engineer','structural engineer','site engineer','construction engineer','planning engineer','estimation engineer'],
  'Electrical Engineer': ['electrical engineer','power systems','control systems','instrumentation','plc programmer','automation engineer','scada engineer'],
  'Marketing Analyst': ['marketing analyst','digital marketing','seo analyst','performance marketing','growth analyst','marketing executive','content strategist','social media'],
  'HR Executive': ['hr executive','hr analyst','talent acquisition','recruiter','hr generalist','hr coordinator','people operations'],
  'Finance Analyst': ['finance analyst','financial analyst','investment analyst','risk analyst','credit analyst','equity research','fp&a','accounts analyst'],
};

function jobMatchesPreferredRole(jobTitle, preferredRole) {
  if (!preferredRole || preferredRole === 'Other') return true;
  return roleTitleSimilarity(jobTitle, preferredRole) >= 25;
}

/* ================================================================
   RELATED TITLE EXPANSION — for broadening search when results are thin
   ================================================================ */
const RELATED_TITLES = {
  'VLSI Engineer': ['RTL Engineer','Senior RTL Engineer','ASIC Design Engineer','FPGA Engineer','Digital Design Engineer','Verification Engineer','DFT Engineer','STA Engineer','Chip Design Engineer','Layout Engineer','Semiconductor Engineer','Silicon Engineer','IC Design Engineer'],
  'RTL Design Engineer': ['RTL Engineer','Senior RTL Engineer','ASIC Design Engineer','Digital Design Engineer','VLSI Engineer','FPGA Design Engineer','RTL Lead','Digital ASIC Engineer','Verilog Engineer','SystemVerilog Engineer','RTL Design','IC Design Engineer'],
  'ASIC Design Engineer': ['ASIC Engineer','Digital Design Engineer','RTL Design Engineer','Chip Design Engineer','VLSI Engineer','Digital ASIC Engineer','IC Design Engineer','Semiconductor Engineer'],
  'ASIC Verification Engineer': ['Design Verification Engineer','DV Engineer','Verification Engineer','UVM Engineer','Functional Verification','ASIC Verification','Verification Lead','Silicon Verification Engineer'],
  'FPGA Engineer': ['FPGA Design Engineer','FPGA Developer','Digital Design Engineer','RTL Engineer','Embedded FPGA','FPGA Verification Engineer','Xilinx Engineer','FPGA Programmer'],
  'Physical Design Engineer': ['Physical Design','Physical Design Lead','PD Engineer','Physical Implementation Engineer','Backend Physical Design Engineer','Physical Verification Engineer','ASIC Physical Design Engineer','VLSI Physical Design Engineer','Physical Design IC Engineer','Layout Engineer','STA Engineer','Floorplan Engineer','Place and Route Engineer','Backend Design Engineer','Physical Design Intern','Senior Physical Design Engineer','Staff Physical Design Engineer','ICC2 Engineer','Innovus Engineer','APR Engineer','ASIC Backend Engineer','Chip Implementation Engineer','Physical Design Analyst'],
  'DFT Engineer': ['DFT Engineer','Design for Test Engineer','DFT Lead','ATPG Engineer','Scan Engineer','BIST Engineer','DFT Architect','Test Engineer VLSI'],
  'STA Engineer': ['STA Engineer','Static Timing Analysis Engineer','Timing Engineer','Timing Closure Engineer','STA Lead','Timing Analysis Engineer','Signoff Engineer'],
  'Frontend Developer': ['React Developer','UI Developer','JavaScript Developer','Web Developer','Angular Developer','Vue Developer','Frontend Engineer','Next.js Developer','TypeScript Developer','UI Engineer'],
  'Backend Developer': ['Node.js Developer','Python Developer','Java Developer','API Developer','Server Developer','Backend Engineer','Django Developer','Spring Boot Developer','Go Developer','.NET Developer','Express.js Developer'],
  'Full Stack Developer': ['Software Engineer','Web Developer','MERN Developer','Full Stack Engineer','Application Developer','MEAN Developer','Software Developer','Web Application Developer'],
  'Data Analyst': ['Business Analyst','BI Analyst','SQL Analyst','Reporting Analyst','Analytics Analyst','Data Analytics','Junior Analyst','MIS Analyst','Product Analyst','Junior Data Analyst','Analytics Associate'],
  'Data Scientist': ['ML Engineer','Applied Scientist','Research Scientist','Data Science','AI Researcher','Machine Learning Scientist','Quantitative Analyst','Statistical Analyst'],
  'AI/ML Engineer': ['AI Engineer','ML Engineer','Machine Learning Engineer','Deep Learning Engineer','NLP Engineer','Computer Vision Engineer','MLOps Engineer','AI Researcher','AI Developer','Applied ML Engineer'],
  'DevOps Engineer': ['SRE','Platform Engineer','Infrastructure Engineer','Cloud DevOps','CI/CD Engineer','Release Engineer','Build Engineer','Site Reliability Engineer'],
  'Cloud Engineer': ['AWS Engineer','Azure Engineer','Cloud Architect','Cloud DevOps','Solutions Architect','GCP Engineer','Cloud Infrastructure Engineer','Cloud Solutions Engineer'],
  'QA Engineer': ['Test Engineer','SDET','Automation Tester','Quality Analyst','Test Automation Engineer','Performance Tester','Manual Tester','QA Analyst','Software Tester'],
  'Mobile Developer': ['Android Developer','iOS Developer','React Native Developer','Flutter Developer','App Developer','Mobile App Developer','Swift Developer','Kotlin Developer'],
  'Embedded Engineer': ['Firmware Engineer','Embedded Systems Engineer','RTOS Developer','IoT Engineer','Microcontroller Engineer','Embedded Software Engineer','Embedded Linux Developer','Embedded C Developer'],
  'Cybersecurity Analyst': ['Security Analyst','Information Security Analyst','SOC Analyst','Security Engineer','Penetration Tester','Threat Analyst','Security Consultant','Cybersecurity Engineer'],
  'UI/UX Designer': ['UX Designer','UI Designer','Product Designer','Interaction Designer','Visual Designer','UX Researcher','UX/UI Designer'],
  'Data Engineer': ['ETL Developer','Data Pipeline Engineer','Big Data Engineer','Analytics Engineer','Data Warehouse Engineer','Data Infrastructure Engineer','Spark Engineer'],
  'Product Manager': ['Associate Product Manager','Technical Product Manager','Product Owner','Program Manager','Product Lead','APM'],
  'Mechanical Engineer': ['Design Engineer','CAD Engineer','Manufacturing Engineer','Production Engineer','R&D Engineer','Mechanical Design Engineer','Automotive Engineer'],
  'Civil Engineer': ['Structural Engineer','Site Engineer','Construction Engineer','Planning Engineer','Estimation Engineer','Project Engineer Civil'],
  'Electrical Engineer': ['Power Systems Engineer','Control Systems Engineer','Instrumentation Engineer','PLC Programmer','Automation Engineer','Electrical Design Engineer'],
  'Marketing Analyst': ['Digital Marketing Analyst','SEO Analyst','Growth Analyst','Marketing Executive','Content Strategist','Social Media Analyst','Performance Marketing'],
  'HR Executive': ['HR Analyst','Talent Acquisition Specialist','Recruiter','HR Generalist','HR Coordinator','People Operations'],
  'Finance Analyst': ['Financial Analyst','Investment Analyst','Risk Analyst','Credit Analyst','FP&A Analyst','Equity Research Analyst'],
};

function getExpandedQueries(selectedRoles) {
  const expanded = new Set();
  for (const role of selectedRoles) {
    expanded.add(role);
    const related = RELATED_TITLES[role];
    if (related) related.forEach(r => expanded.add(r));
    const aliases = ROLE_ALIASES[role];
    if (aliases) aliases.slice(0, 8).forEach(a => { if (a.length > 4) expanded.add(a); });
  }
  return [...expanded];
}

/* ================================================================
   BUILD SEARCH QUERIES FROM PROFILE
   ================================================================ */
function buildSearchQueries(profile) {
  const queries = [];
  const selectedRoles = profile.selectedRoles || [];
  const preferredRole = profile.preferredRole;

  if (selectedRoles.length > 0) {
    selectedRoles.slice(0, 5).forEach(r => queries.push(r));
  } else if (preferredRole && preferredRole !== 'Other') {
    queries.push(preferredRole);
    const aliases = ROLE_ALIASES[preferredRole];
    if (aliases) {
      aliases.slice(0, 3).forEach(a => {
        if (a.toLowerCase() !== preferredRole.toLowerCase()) queries.push(a);
      });
    }
  }

  if (profile.aiSearchQueries && profile.aiSearchQueries.length > 0 && queries.length < 8) {
    profile.aiSearchQueries.slice(0, 3).forEach(q => queries.push(q));
  }

  if (selectedRoles.length > 0 && queries.length < 10) {
    for (const role of selectedRoles.slice(0, 3)) {
      const related = RELATED_TITLES[role];
      if (related) {
        related.slice(0, 3).forEach(r => { if (!queries.includes(r)) queries.push(r); });
      }
    }
  }

  if (queries.length === 0) {
    const roles = profile.targetRoles || [];
    const skills = profile.skills || [];
    const domain = detectDomain(skills);
    if (roles.length > 0) roles.slice(0, 4).forEach(r => queries.push(r));
    if (domain !== 'General') queries.push(domain + ' engineer');
    const topSkills = skills.slice(0, 4);
    if (topSkills.length >= 2) queries.push(topSkills.slice(0, 3).join(' ') + ' developer');
    if (queries.length === 0) queries.push(skills.slice(0, 3).join(' ') + ' jobs');
  }

  return [...new Set(queries)].slice(0, 10);
}

/* ================================================================
   MULTI-KEY ROTATION + RATE-LIMIT COOLDOWN + SOURCE HEALTH TRACKING
   ================================================================ */
function getApiKeys(envPrefix) {
  const keys = [];
  const primary = process.env[envPrefix];
  if (primary && !primary.startsWith('your_')) keys.push(primary);
  for (let i = 1; i <= 10; i++) {
    const k = process.env[`${envPrefix}_${i}`];
    if (k && !k.startsWith('your_')) keys.push(k);
  }
  return keys;
}

const rateLimitCooldowns = new Map();
const COOLDOWN_MS = 10 * 60 * 1000;

function isRateLimited(source) {
  const until = rateLimitCooldowns.get(source);
  if (!until) return false;
  if (Date.now() > until) { rateLimitCooldowns.delete(source); return false; }
  return true;
}

function markRateLimited(source) {
  rateLimitCooldowns.set(source, Date.now() + COOLDOWN_MS);
  trackFailure(source, true);
  console.log(`[RateLimit] ${source} cooled down for ${COOLDOWN_MS / 60000} minutes`);
}

function isRateLimitStatus(status) {
  return status === 429 || status === 402 || status === 503;
}

/* ---- Source Health Tracking ---- */
const sourceHealth = {};
const ALL_SOURCES = ['jsearch','adzuna','jooble','greenhouse','lever','smartrecruiters','ashby','workday','themuse','arbeitnow','remoteok'];
for (const s of ALL_SOURCES) {
  sourceHealth[s] = {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    rateLimitCount: 0,
    totalResponseTime: 0,
    lastSuccessTime: null,
    lastFailureTime: null,
  };
}

function trackSuccess(source, responseTimeMs, jobCount) {
  const h = sourceHealth[source];
  if (!h) return;
  h.totalRequests++;
  h.successfulRequests++;
  h.totalResponseTime += responseTimeMs;
  h.lastSuccessTime = Date.now();
}

function trackFailure(source, isRateLimit) {
  const h = sourceHealth[source];
  if (!h) return;
  h.totalRequests++;
  h.failedRequests++;
  if (isRateLimit) h.rateLimitCount++;
  h.lastFailureTime = Date.now();
}

function getSourceScore(source) {
  const h = sourceHealth[source];
  if (!h || h.totalRequests === 0) return 50;
  const successRate = h.successfulRequests / h.totalRequests;
  const avgMs = h.totalRequests > 0 ? h.totalResponseTime / h.successfulRequests : 5000;
  const speedScore = Math.max(0, 100 - (avgMs / 100));
  return Math.round(successRate * 70 + speedScore * 0.3);
}

function getHealthSnapshot() {
  const snapshot = {};
  for (const s of ALL_SOURCES) {
    const h = sourceHealth[s];
    const avg = h.successfulRequests > 0 ? Math.round(h.totalResponseTime / h.successfulRequests) : 0;
    snapshot[s] = {
      ...h,
      averageResponseTime: avg,
      successRate: h.totalRequests > 0 ? Math.round((h.successfulRequests / h.totalRequests) * 100) : 0,
      score: getSourceScore(s),
      rateLimited: isRateLimited(s),
      cooldownUntil: rateLimitCooldowns.get(s) || null,
    };
  }
  return snapshot;
}

/* ---- Instrumented fetch wrapper ---- */
async function trackedSearch(source, searchFn) {
  const start = Date.now();
  try {
    const results = await searchFn();
    const elapsed = Date.now() - start;
    if (results.length > 0) {
      trackSuccess(source, elapsed, results.length);
    } else {
      trackSuccess(source, elapsed, 0);
    }
    return results;
  } catch (e) {
    trackFailure(source, false);
    return [];
  }
}

/* ================================================================
   API SOURCE 1: JSEARCH (RapidAPI) — multi-key support
   ================================================================ */
async function searchJSearch(query, location) {
  if (isRateLimited('jsearch')) return [];
  const keys = getApiKeys('JSEARCH_API_KEY');
  if (keys.length === 0) return [];

  const params = new URLSearchParams({
    query: `${query} in ${location || 'India'}`,
    num_pages: '1',
    date_posted: 'month',
    country: 'in'
  });

  for (const apiKey of keys) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`https://jsearch.p.rapidapi.com/search-v2?${params}`, {
        headers: {
          'x-rapidapi-key': apiKey,
          'x-rapidapi-host': 'jsearch.p.rapidapi.com'
        },
        signal: controller.signal
      });
      clearTimeout(timer);

      if (isRateLimitStatus(res.status)) {
        console.error(`[JSearch] Key ${apiKey.slice(0,8)}… rate-limited (${res.status}), trying next`);
        continue;
      }
      if (!res.ok) {
        console.error('[JSearch] HTTP', res.status);
        return [];
      }

      const data = await res.json();
      const jobs = data?.data?.jobs || [];

      return jobs.map(j => ({
        company: j.employer_name || '',
        title: j.job_title || '',
        location: j.job_location || j.job_city || j.job_state || '',
        applyLink: j.job_apply_link || j.apply_options?.[0]?.apply_link || '',
        sourceLink: j.job_google_link || j.job_apply_link || '',
        foundVia: j.job_publisher || 'JSearch',
        description: (j.job_description || '').slice(0, 500),
        skills: extractSkillsFromDescription(j.job_description || ''),
        datePosted: j.job_posted_at_datetime_utc || '',
        isRemote: j.job_is_remote || false,
        employmentType: j.job_employment_type || '',
        salary: j.job_min_salary && j.job_max_salary ? `${j.job_salary_currency || '$'}${j.job_min_salary.toLocaleString()} – ${j.job_max_salary.toLocaleString()} ${j.job_salary_period || ''}`.trim() : '',
        experienceRequired: j.job_required_experience ? `${j.job_required_experience.required_experience_in_months ? Math.round(j.job_required_experience.required_experience_in_months/12) + ' yrs' : ''}${j.job_required_experience.experience_mentioned ? '' : ''}`.trim() || '' : '',
        source: 'jsearch'
      })).filter(j => j.company && j.title && j.applyLink);
    } catch (e) {
      if (e.name === 'AbortError') console.error('[JSearch] Timeout');
      else console.error('[JSearch] Error:', e.message);
    }
  }
  markRateLimited('jsearch');
  return [];
}

/* ================================================================
   API SOURCE 2: ADZUNA
   ================================================================ */
async function searchAdzuna(query, location) {
  if (isRateLimited('adzuna')) return [];
  const appIds = getApiKeys('ADZUNA_APP_ID');
  const apiKeys = getApiKeys('ADZUNA_API_KEY');
  if (appIds.length === 0 || apiKeys.length === 0) return [];

  for (let i = 0; i < Math.max(appIds.length, apiKeys.length); i++) {
    const appId = appIds[i] || appIds[0];
    const apiKey = apiKeys[i] || apiKeys[0];
    try {
      const params = new URLSearchParams({
        app_id: appId, app_key: apiKey, results_per_page: '20',
        what: query, where: location || 'India', max_days_old: '30',
        sort_by: 'relevance', content_type: 'application/json'
      });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`https://api.adzuna.com/v1/api/jobs/in/search/1?${params}`, { signal: controller.signal });
      clearTimeout(timer);
      if (isRateLimitStatus(res.status)) {
        console.error(`[Adzuna] Key ${i} rate-limited (${res.status}), trying next`);
        continue;
      }
      if (!res.ok) { console.error('[Adzuna] HTTP', res.status); return []; }
      const data = await res.json();
      return (data.results || []).map(j => ({
        company: j.company?.display_name || '',
        title: j.title || '',
        location: j.location?.display_name || '',
        applyLink: j.redirect_url || '',
        sourceLink: j.redirect_url || '',
        foundVia: 'Adzuna',
        description: (j.description || '').slice(0, 500),
        skills: extractSkillsFromDescription(j.description || ''),
        datePosted: j.created || '',
        isRemote: /remote/i.test(j.title + ' ' + (j.location?.display_name || '')),
        employmentType: j.contract_type || '',
        salary: j.salary_min && j.salary_max ? `₹${Math.round(j.salary_min).toLocaleString()} – ₹${Math.round(j.salary_max).toLocaleString()}` : '',
        experienceRequired: '',
        source: 'adzuna'
      })).filter(j => j.company && j.title && j.applyLink);
    } catch (e) {
      if (e.name === 'AbortError') console.error('[Adzuna] Timeout');
      else console.error('[Adzuna] Error:', e.message);
    }
  }
  markRateLimited('adzuna');
  return [];
}

/* ================================================================
   API SOURCE 3: ARBEITNOW (free, no key required)
   ================================================================ */
async function searchArbeitnow(query) {
  if (isRateLimited('arbeitnow')) return [];
  try {
    const res = await fetch('https://www.arbeitnow.com/api/job-board-api', {
      headers: { 'Accept': 'application/json' }
    });
    if (isRateLimitStatus(res.status)) { markRateLimited('arbeitnow'); return []; }
    if (!res.ok) { console.error('[Arbeitnow] HTTP', res.status); return []; }
    const data = await res.json();
    const queryWords = query.toLowerCase().split(/\s+/).filter(w => w.length > 2);
    return (data.data || [])
      .filter(j => {
        const text = ((j.title || '') + ' ' + (j.company_name || '') + ' ' + (j.description || '') + ' ' + (j.tags || []).join(' ')).toLowerCase();
        return queryWords.some(w => text.includes(w));
      })
      .slice(0, 15)
      .map(j => ({
        company: j.company_name || '',
        title: j.title || '',
        location: j.location || '',
        applyLink: j.url || '',
        sourceLink: j.url || '',
        foundVia: 'Arbeitnow',
        description: ((j.description || '').replace(/<[^>]*>/g, ' ')).slice(0, 500),
        skills: extractSkillsFromDescription((j.description || '').replace(/<[^>]*>/g, ' ') + ' ' + (j.tags || []).join(' ')),
        datePosted: j.created_at ? new Date(j.created_at * 1000).toISOString() : '',
        isRemote: j.remote || /remote/i.test((j.title || '') + ' ' + (j.location || '')),
        employmentType: j.job_types ? j.job_types.join(', ') : '',
        source: 'arbeitnow'
      }))
      .filter(j => j.company && j.title && j.applyLink);
  } catch (e) {
    console.error('[Arbeitnow] Error:', e.message);
    return [];
  }
}

/* ================================================================
   API SOURCE 4: REMOTEOK (free, no key)
   ================================================================ */
async function searchRemoteOK(query) {
  if (isRateLimited('remoteok')) return [];
  try {
    const tag = query.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
    const res = await fetch(`https://remoteok.com/api?tag=${tag}`, {
      headers: { 'User-Agent': 'CareerAI/2.0' }
    });
    if (isRateLimitStatus(res.status)) { markRateLimited('remoteok'); return []; }
    if (!res.ok) { console.error('[RemoteOK] HTTP', res.status); return []; }
    const data = await res.json();
    const jobs = Array.isArray(data) ? data.filter(j => j.id && j.company) : [];
    return jobs.slice(0, 15).map(j => ({
      company: j.company || '',
      title: j.position || '',
      location: j.location || 'Remote',
      applyLink: j.url || `https://remoteok.com/l/${j.id}`,
      sourceLink: j.url || `https://remoteok.com/l/${j.id}`,
      foundVia: 'RemoteOK',
      description: ((j.description || '').replace(/<[^>]*>/g, ' ')).slice(0, 500),
      skills: extractSkillsFromDescription((j.description || '') + ' ' + (j.tags || []).join(' ')),
      datePosted: j.date || '',
      isRemote: true,
      employmentType: 'Full-time',
      source: 'remoteok'
    })).filter(j => j.company && j.title && j.applyLink);
  } catch (e) {
    console.error('[RemoteOK] Error:', e.message);
    return [];
  }
}

/* ================================================================
   API SOURCE 5: THE MUSE (free, no key)
   ================================================================ */
async function searchTheMuse(query, location) {
  if (isRateLimited('themuse')) return [];
  try {
    const params = new URLSearchParams({ page: '0', descending: 'true' });
    if (location) params.set('location', location);

    const res = await fetch(`https://www.themuse.com/api/public/jobs?${params}`, {
      headers: { 'Accept': 'application/json' }
    });
    if (isRateLimitStatus(res.status)) { markRateLimited('themuse'); return []; }
    if (!res.ok) { console.error('[TheMuse] HTTP', res.status); return []; }
    const data = await res.json();
    const queryLower = query.toLowerCase();
    return (data.results || [])
      .filter(j => {
        const text = ((j.name || '') + ' ' + (j.company?.name || '') + ' ' + (j.contents || '')).toLowerCase();
        return queryLower.split(/\s+/).some(w => text.includes(w));
      })
      .slice(0, 15)
      .map(j => ({
        company: j.company?.name || '',
        title: j.name || '',
        location: (j.locations || []).map(l => l.name).join(', ') || '',
        applyLink: j.refs?.landing_page || '',
        sourceLink: j.refs?.landing_page || '',
        foundVia: 'The Muse',
        description: ((j.contents || '').replace(/<[^>]*>/g, ' ')).slice(0, 500),
        skills: extractSkillsFromDescription((j.contents || '').replace(/<[^>]*>/g, ' ')),
        datePosted: j.publication_date || '',
        isRemote: (j.locations || []).some(l => /remote|flexible/i.test(l.name)),
        employmentType: (j.levels || []).map(l => l.name).join(', ') || '',
        source: 'themuse'
      }))
      .filter(j => j.company && j.title && j.applyLink);
  } catch (e) {
    console.error('[TheMuse] Error:', e.message);
    return [];
  }
}

/* ================================================================
   API SOURCE 6: JOOBLE (free tier, API key required)
   ================================================================ */
async function searchJooble(query, location) {
  if (isRateLimited('jooble')) return [];
  const keys = getApiKeys('JOOBLE_API_KEY');
  if (keys.length === 0) return [];

  for (const apiKey of keys) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(`https://jooble.org/api/${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keywords: query, location: location || 'India', page: 1 }),
        signal: controller.signal
      });
      clearTimeout(timer);
      if (isRateLimitStatus(res.status)) {
        console.error(`[Jooble] Key ${apiKey.slice(0,8)}… rate-limited (${res.status}), trying next`);
        continue;
      }
      if (!res.ok) { console.error('[Jooble] HTTP', res.status); return []; }
      const data = await res.json();
      return (data.jobs || []).slice(0, 20).map(j => ({
        company: j.company || '',
        title: j.title || '',
        location: j.location || '',
        applyLink: j.link || '',
        sourceLink: j.link || '',
        foundVia: 'Jooble',
        description: ((j.snippet || '').replace(/<[^>]*>/g, ' ')).slice(0, 500),
        skills: extractSkillsFromDescription((j.snippet || '').replace(/<[^>]*>/g, ' ')),
        datePosted: j.updated || '',
        isRemote: /remote/i.test((j.title || '') + ' ' + (j.location || '')),
        employmentType: j.type || '',
        salary: j.salary || '',
        experienceRequired: '',
        source: 'jooble'
      })).filter(j => j.company && j.title && j.applyLink);
    } catch (e) {
      if (e.name === 'AbortError') console.error('[Jooble] Timeout');
      else console.error('[Jooble] Error:', e.message);
    }
  }
  markRateLimited('jooble');
  return [];
}

/* ================================================================
   API SOURCE 7: GREENHOUSE (company ATS boards, free, no key)
   ================================================================ */
const GREENHOUSE_BOARDS = {
  'General':      ['cloudflare','gitlab','figma','stripe','hashicorp','coinbase','notion','discord','datadog','hubspot','gusto','lyft','duolingo','squarespace','twitch'],
  'Software':     ['cloudflare','gitlab','figma','stripe','hashicorp','coinbase','notion','discord','datadog','hubspot','gusto','squarespace','twitch'],
  'Full Stack':   ['gitlab','stripe','coinbase','notion','discord','hubspot','cloudflare'],
  'Frontend':     ['figma','squarespace','hubspot','notion','discord','stripe'],
  'Backend':      ['cloudflare','hashicorp','stripe','coinbase','datadog','gitlab'],
  'AI/ML':        ['datadog','coinbase','notion','discord'],
  'Data Science': ['datadog','hubspot','lyft','coinbase'],
  'Cloud':        ['cloudflare','hashicorp','datadog','gitlab'],
  'DevOps':       ['cloudflare','hashicorp','datadog','gitlab'],
  'Mobile':       ['lyft','duolingo','discord'],
  'VLSI/ECE':     ['marvell'],
  'Embedded':     ['cloudflare'],
  'Cybersecurity':['cloudflare','hashicorp'],
  'Testing/QA':   ['gitlab','datadog','hubspot'],
  'UI/UX':        ['figma','squarespace','notion'],
};

async function searchGreenhouse(queries, domain) {
  if (isRateLimited('greenhouse')) return [];
  const boards = GREENHOUSE_BOARDS[domain] || GREENHOUSE_BOARDS['General'];
  const queryWords = [...new Set(queries.flatMap(q => q.toLowerCase().split(/\s+/)).filter(w => w.length > 2))];

  const results = await Promise.allSettled(
    boards.slice(0, 10).map(async (board) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const res = await fetch(`https://boards-api.greenhouse.io/v1/boards/${board}/jobs`, {
          headers: { 'Accept': 'application/json' },
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) return [];
        const data = await res.json();
        return (data.jobs || [])
          .filter(j => {
            const t = (j.title || '').toLowerCase();
            return queryWords.some(w => t.includes(w));
          })
          .slice(0, 5)
          .map(j => ({
            company: board.charAt(0).toUpperCase() + board.slice(1),
            title: j.title || '',
            location: j.location?.name || '',
            applyLink: j.absolute_url || '',
            sourceLink: j.absolute_url || '',
            foundVia: 'Greenhouse',
            description: '',
            skills: [],
            datePosted: j.updated_at || '',
            isRemote: /remote/i.test(j.location?.name || ''),
            employmentType: '',
            experienceRequired: '',
            source: 'greenhouse'
          }));
      } catch { return []; }
    })
  );

  const all = [];
  for (const r of results) {
    if (r.status === 'fulfilled') all.push(...r.value);
  }
  return all.filter(j => j.company && j.title && j.applyLink);
}

/* ================================================================
   API SOURCE 8: LEVER (company ATS boards, free, no key)
   ================================================================ */
const LEVER_BOARDS = {
  'General':    ['netflix','twilio','netlify','postman','grafanalabs','sentry','supabase'],
  'Software':   ['netflix','twilio','netlify','postman','grafanalabs','sentry','supabase'],
  'Full Stack': ['netflix','twilio','netlify','supabase'],
  'Frontend':   ['netlify','supabase','postman'],
  'Backend':    ['netflix','twilio','sentry','supabase','grafanalabs'],
  'DevOps':     ['grafanalabs','netlify','sentry'],
  'Cloud':      ['netlify','grafanalabs'],
  'Data Science':['netflix','twilio'],
  'AI/ML':      [],
  'VLSI/ECE':   [],
  'Embedded':   [],
  'Testing/QA': ['sentry','postman'],
};

async function searchLever(queries, domain) {
  if (isRateLimited('lever')) return [];
  const boards = LEVER_BOARDS[domain] || LEVER_BOARDS['General'];
  if (boards.length === 0) return [];
  const queryWords = [...new Set(queries.flatMap(q => q.toLowerCase().split(/\s+/)).filter(w => w.length > 2))];

  const results = await Promise.allSettled(
    boards.slice(0, 8).map(async (company) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const res = await fetch(`https://api.lever.co/v0/postings/${company}?mode=json`, {
          headers: { 'Accept': 'application/json' },
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) return [];
        const data = await res.json();
        return (Array.isArray(data) ? data : [])
          .filter(j => {
            const t = (j.text || '').toLowerCase();
            return queryWords.some(w => t.includes(w));
          })
          .slice(0, 5)
          .map(j => ({
            company: company.charAt(0).toUpperCase() + company.slice(1),
            title: j.text || '',
            location: j.categories?.location || '',
            applyLink: j.hostedUrl || j.applyUrl || '',
            sourceLink: j.hostedUrl || '',
            foundVia: 'Lever',
            description: ((j.descriptionPlain || '').slice(0, 500)),
            skills: extractSkillsFromDescription(j.descriptionPlain || ''),
            datePosted: j.createdAt ? new Date(j.createdAt).toISOString() : '',
            isRemote: /remote/i.test(j.categories?.location || ''),
            employmentType: j.categories?.commitment || '',
            experienceRequired: '',
            source: 'lever'
          }));
      } catch { return []; }
    })
  );

  const all = [];
  for (const r of results) {
    if (r.status === 'fulfilled') all.push(...r.value);
  }
  return all.filter(j => j.company && j.title && j.applyLink);
}

/* ================================================================
   API SOURCE 9: SMARTRECRUITERS (company ATS, free, no key)
   ================================================================ */
const SMARTRECRUITERS_COMPANIES = {
  'General':      ['VISA','Bosch','Adidas','Equinix','SmartRecruiters'],
  'Software':     ['VISA','Bosch','Equinix','SmartRecruiters'],
  'Full Stack':   ['VISA','Bosch','Equinix'],
  'AI/ML':        ['VISA','Bosch'],
  'Data Science': ['VISA','Bosch'],
  'Cloud':        ['Equinix','VISA'],
  'DevOps':       ['Equinix','Bosch'],
  'VLSI/ECE':     ['Bosch'],
  'Embedded':     ['Bosch'],
  'Electrical':   ['Bosch'],
  'Mechanical':   ['Bosch','Adidas'],
  'HR':           ['Adidas','SmartRecruiters'],
  'Marketing':    ['Adidas'],
  'Finance':      ['VISA'],
};

async function searchSmartRecruiters(queries, domain) {
  if (isRateLimited('smartrecruiters')) return [];
  const companies = SMARTRECRUITERS_COMPANIES[domain] || SMARTRECRUITERS_COMPANIES['General'];
  const queryWords = [...new Set(queries.flatMap(q => q.toLowerCase().split(/\s+/)).filter(w => w.length > 2))];

  const results = await Promise.allSettled(
    companies.slice(0, 6).map(async (company) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const params = new URLSearchParams({ limit: '50' });
        const res = await fetch(`https://api.smartrecruiters.com/v1/companies/${encodeURIComponent(company)}/postings?${params}`, {
          headers: { 'Accept': 'application/json' },
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) return [];
        const data = await res.json();
        return (data.content || [])
          .filter(j => {
            const t = (j.name || '').toLowerCase();
            return queryWords.some(w => t.includes(w));
          })
          .slice(0, 5)
          .map(j => ({
            company: j.company?.name || company,
            title: j.name || '',
            location: j.location ? [j.location.city, j.location.region, j.location.country].filter(Boolean).join(', ') : '',
            applyLink: j.ref || j.applyUrl || `https://jobs.smartrecruiters.com/${encodeURIComponent(company)}/${j.id}`,
            sourceLink: j.ref || '',
            foundVia: 'SmartRecruiters',
            description: '',
            skills: [],
            datePosted: j.releasedDate || '',
            isRemote: j.location?.remote || /remote/i.test(j.name || ''),
            employmentType: j.typeOfEmployment?.label || '',
            experienceRequired: j.experienceLevel?.label || '',
            source: 'smartrecruiters'
          }));
      } catch { return []; }
    })
  );

  const all = [];
  for (const r of results) {
    if (r.status === 'fulfilled') all.push(...r.value);
  }
  return all.filter(j => j.company && j.title && j.applyLink);
}

/* ================================================================
   API SOURCE 10: ASHBY (company ATS boards, free, no key)
   ================================================================ */
const ASHBY_BOARDS = {
  'General':    ['notion','ramp','openai','anthropic','figma','vercel','linear','retool','deel','brex'],
  'Software':   ['ramp','vercel','linear','retool','brex','notion','deel'],
  'Full Stack': ['ramp','vercel','linear','retool','notion'],
  'Frontend':   ['vercel','linear','retool','notion','figma'],
  'Backend':    ['ramp','vercel','linear','supabase','retool'],
  'AI/ML':      ['openai','anthropic','ramp'],
  'Data Science':['ramp','brex','notion'],
  'Cloud':      ['vercel','deel'],
  'DevOps':     ['vercel','linear','deel'],
  'UI/UX':      ['figma','linear','notion'],
  'Finance':    ['ramp','brex'],
  'HR':         ['deel'],
  'VLSI/ECE':   [],
  'Embedded':   [],
};

async function searchAshby(queries, domain) {
  if (isRateLimited('ashby')) return [];
  const boards = ASHBY_BOARDS[domain] || ASHBY_BOARDS['General'];
  if (boards.length === 0) return [];
  const queryWords = [...new Set(queries.flatMap(q => q.toLowerCase().split(/\s+/)).filter(w => w.length > 2))];

  const results = await Promise.allSettled(
    boards.slice(0, 8).map(async (org) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const res = await fetch(`https://api.ashbyhq.com/posting-api/job-board/${org}`, {
          headers: { 'Accept': 'application/json' },
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) return [];
        const data = await res.json();
        return (data.jobs || [])
          .filter(j => {
            const t = (j.title || '').toLowerCase();
            return queryWords.some(w => t.includes(w));
          })
          .slice(0, 5)
          .map(j => ({
            company: org.charAt(0).toUpperCase() + org.slice(1),
            title: j.title || '',
            location: j.location || '',
            applyLink: j.jobUrl || j.applyUrl || '',
            sourceLink: j.jobUrl || '',
            foundVia: 'Ashby',
            description: ((j.descriptionPlain || j.description || '').replace(/<[^>]*>/g, ' ')).slice(0, 500),
            skills: extractSkillsFromDescription((j.descriptionPlain || j.description || '').replace(/<[^>]*>/g, ' ')),
            datePosted: j.publishedAt || '',
            isRemote: j.isRemote || /remote/i.test(j.location || ''),
            employmentType: j.employmentType || '',
            experienceRequired: '',
            source: 'ashby'
          }));
      } catch { return []; }
    })
  );

  const all = [];
  for (const r of results) {
    if (r.status === 'fulfilled') all.push(...r.value);
  }
  return all.filter(j => j.company && j.title && j.applyLink);
}

/* ================================================================
   API SOURCE 11: WORKDAY (company career pages, free, no key)
   Workday career sites use a JSON endpoint per company.
   ================================================================ */
const WORKDAY_SITES = {
  'General':      [{id:'intel',       url:'https://intel.wd1.myworkdayjobs.com/wday/cxs/intel/External/jobs'},
                   {id:'salesforce',  url:'https://salesforce.wd12.myworkdayjobs.com/wday/cxs/salesforce/External/jobs'},
                   {id:'amazon',      url:'https://www.amazon.jobs/api/search-jobs'}],
  'Software':     [{id:'intel',       url:'https://intel.wd1.myworkdayjobs.com/wday/cxs/intel/External/jobs'},
                   {id:'salesforce',  url:'https://salesforce.wd12.myworkdayjobs.com/wday/cxs/salesforce/External/jobs'}],
  'VLSI/ECE':     [{id:'intel',       url:'https://intel.wd1.myworkdayjobs.com/wday/cxs/intel/External/jobs'}],
  'Embedded':     [{id:'intel',       url:'https://intel.wd1.myworkdayjobs.com/wday/cxs/intel/External/jobs'}],
  'Cloud':        [{id:'salesforce',  url:'https://salesforce.wd12.myworkdayjobs.com/wday/cxs/salesforce/External/jobs'}],
  'AI/ML':        [{id:'intel',       url:'https://intel.wd1.myworkdayjobs.com/wday/cxs/intel/External/jobs'}],
};

async function searchWorkday(queries, domain, location) {
  if (isRateLimited('workday')) return [];
  const sites = WORKDAY_SITES[domain] || WORKDAY_SITES['General'];
  if (!sites || sites.length === 0) return [];
  const queryString = queries.slice(0, 2).join(' ');

  const results = await Promise.allSettled(
    sites.slice(0, 4).map(async (site) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 6000);
        const res = await fetch(site.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({
            appliedFacets: {},
            limit: 20,
            offset: 0,
            searchText: queryString,
          }),
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) return [];
        const data = await res.json();
        const postings = data.jobPostings || [];
        return postings.slice(0, 10).map(j => ({
          company: site.id.charAt(0).toUpperCase() + site.id.slice(1),
          title: j.title || j.bulletFields?.[0] || '',
          location: j.locationsText || j.bulletFields?.[1] || '',
          applyLink: j.externalPath ? (site.url.replace('/wday/cxs/' + site.id + '/External/jobs', '') + j.externalPath) : '',
          sourceLink: '',
          foundVia: 'Workday',
          description: '',
          skills: [],
          datePosted: j.postedOn || '',
          isRemote: /remote/i.test(j.locationsText || ''),
          employmentType: '',
          experienceRequired: '',
          source: 'workday'
        }));
      } catch { return []; }
    })
  );

  const all = [];
  for (const r of results) {
    if (r.status === 'fulfilled') all.push(...r.value);
  }
  return all.filter(j => j.company && j.title && j.applyLink);
}

/* ================================================================
   LINK VALIDATION
   ================================================================ */
async function validateLink(url, timeoutMs = 4000) {
  if (!url) return false;
  try { new URL(url); } catch { return false; }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
    clearTimeout(timer);
    return res.ok || res.status === 405 || res.status === 403 || res.status === 301 || res.status === 302;
  } catch {
    return false;
  }
}

/* ================================================================
   DEDUPLICATION — uses company + title + location
   Source priority: lower number = higher priority (kept on conflict)
   ================================================================ */
const SOURCE_PRIORITY = {
  jsearch: 1, adzuna: 2, jooble: 3,
  greenhouse: 4, lever: 5, smartrecruiters: 6,
  workday: 7, ashby: 8,
  themuse: 9, arbeitnow: 10, remoteok: 11,
};

function sourcePriority(job) {
  return SOURCE_PRIORITY[job.source] || 99;
}

function deduplicationKey(job) {
  return (job.company + '|' + job.title + '|' + job.location).toLowerCase().replace(/\s+/g, '');
}

/* ================================================================
   MAIN JOB SEARCH ENDPOINT
   POST /api/jobs/search
   ================================================================ */
app.post('/api/jobs/search', async (req, res) => {
  const { profile, location, existingKeys = [] } = req.body;
  if (!profile || !profile.skills || !profile.skills.length) {
    return res.status(400).json({ error: 'Upload a resume first — no skills detected.' });
  }

  const preferredRole = profile.preferredRole || '';
  const queries = buildSearchQueries(profile);
  const cacheKey = (preferredRole || 'any-role') + '|' + queries.slice().sort().join('|') + '|' + (location || 'any');
  const cached = getCached(cacheKey);
  if (cached) {
    const filtered = cached.filter(j => !existingKeys.includes(deduplicationKey(j)));
    return res.json({
      jobs: filtered.slice(0, 20),
      source: 'cache',
      summary: `${filtered.length} cached jobs returned.`,
      apiStatus: { cached: true }
    });
  }

  const apiStatus = {};

  try {
    const searchPromises = [];
    const sourceLabels = [];

    for (const q of queries) {
      searchPromises.push(trackedSearch('jsearch', () => searchJSearch(q, location)));
      sourceLabels.push('JSearch');

      searchPromises.push(trackedSearch('adzuna', () => searchAdzuna(q, location)));
      sourceLabels.push('Adzuna');

      searchPromises.push(trackedSearch('jooble', () => searchJooble(q, location)));
      sourceLabels.push('Jooble');

      searchPromises.push(trackedSearch('arbeitnow', () => searchArbeitnow(q)));
      sourceLabels.push('Arbeitnow');

      searchPromises.push(trackedSearch('remoteok', () => searchRemoteOK(q)));
      sourceLabels.push('RemoteOK');

      searchPromises.push(trackedSearch('themuse', () => searchTheMuse(q, location)));
      sourceLabels.push('TheMuse');
    }

    // Company ATS boards — searched once, filtered by query keywords
    const candidateDomain = profile.primaryDomain || detectDomain(profile.skills || []);
    searchPromises.push(trackedSearch('greenhouse', () => searchGreenhouse(queries, candidateDomain)));
    sourceLabels.push('Greenhouse');
    searchPromises.push(trackedSearch('lever', () => searchLever(queries, candidateDomain)));
    sourceLabels.push('Lever');
    searchPromises.push(trackedSearch('smartrecruiters', () => searchSmartRecruiters(queries, candidateDomain)));
    sourceLabels.push('SmartRecruiters');
    searchPromises.push(trackedSearch('ashby', () => searchAshby(queries, candidateDomain)));
    sourceLabels.push('Ashby');
    searchPromises.push(trackedSearch('workday', () => searchWorkday(queries, candidateDomain, location)));
    sourceLabels.push('Workday');

    const results = await Promise.allSettled(searchPromises);

    const allRaw = [];
    const sourceCounts = {};

    for (let i = 0; i < results.length; i++) {
      const label = sourceLabels[i];
      if (results[i].status === 'fulfilled') {
        const jobs = results[i].value;
        allRaw.push(...jobs);
        sourceCounts[label] = (sourceCounts[label] || 0) + jobs.length;
        if (!apiStatus[label]) apiStatus[label] = 'ok';
      } else {
        apiStatus[label] = 'failed';
      }
    }

    const seen = new Map();
    const deduped = [];
    for (const j of allRaw) {
      const key = deduplicationKey(j);
      if (existingKeys.includes(key)) continue;
      const existing = seen.get(key);
      if (existing !== undefined) {
        if (sourcePriority(j) < sourcePriority(deduped[existing])) {
          deduped[existing] = j;
        }
        continue;
      }
      seen.set(key, deduped.length);
      deduped.push(j);
    }

    /* ---- LOCATION CASCADE: broaden location progressively, search ALL sources ---- */
    const CITY_TO_STATE = {
      'Hyderabad':'Telangana','Bengaluru':'Karnataka','Bangalore':'Karnataka',
      'Chennai':'Tamil Nadu','Pune':'Maharashtra','Mumbai':'Maharashtra',
      'Delhi':'Delhi','New Delhi':'Delhi','Noida':'Uttar Pradesh',
      'Greater Noida':'Uttar Pradesh','Gurugram':'Haryana','Gurgaon':'Haryana',
      'Kolkata':'West Bengal','Ahmedabad':'Gujarat','Jaipur':'Rajasthan',
      'Lucknow':'Uttar Pradesh','Kochi':'Kerala','Indore':'Madhya Pradesh',
      'Bhopal':'Madhya Pradesh','Visakhapatnam':'Andhra Pradesh','Vizag':'Andhra Pradesh',
      'Coimbatore':'Tamil Nadu','Mysuru':'Karnataka','Nagpur':'Maharashtra',
      'Thiruvananthapuram':'Kerala','Chandigarh':'Chandigarh','Bhubaneswar':'Odisha',
      'Patna':'Bihar','Ranchi':'Jharkhand','Surat':'Gujarat','Vadodara':'Gujarat',
      'Rajkot':'Gujarat','Faridabad':'Haryana','Ghaziabad':'Uttar Pradesh',
      'Navi Mumbai':'Maharashtra','Thane':'Maharashtra','Nashik':'Maharashtra',
      'Amritsar':'Punjab','Mohali':'Punjab','Ludhiana':'Punjab',
      'Dehradun':'Uttarakhand','Mangalore':'Karnataka','Madurai':'Tamil Nadu',
      'Vijayawada':'Andhra Pradesh','Tirupati':'Andhra Pradesh','Warangal':'Telangana',
    };

    function buildLocationCascade(loc) {
      if (!loc || loc === 'Remote' || loc === 'All Locations') return [];
      const cascade = [];
      if (/delhi\s*ncr/i.test(loc)) {
        cascade.push('India', 'Remote India', 'Remote');
        return cascade;
      }
      const state = CITY_TO_STATE[loc];
      if (state) cascade.push(state);
      cascade.push('India', 'Remote India', 'Remote');
      return cascade;
    }

    const MIN_DEDUPED = 10;
    if (deduped.length < MIN_DEDUPED && location && location !== 'Remote') {
      const cascadeLocs = buildLocationCascade(location);
      for (const broaderLoc of cascadeLocs) {
        if (deduped.length >= MIN_DEDUPED) break;
        console.log(`[Search] Cascade: "${location}" → "${broaderLoc}"`);
        const cascadeQueries = queries.slice(0, 4);
        const cascadePromises = cascadeQueries.flatMap(q => [
          searchJSearch(q, broaderLoc),
          searchAdzuna(q, broaderLoc),
          searchJooble(q, broaderLoc),
          searchTheMuse(q, broaderLoc),
        ]);
        if (broaderLoc === 'Remote' || broaderLoc === 'Remote India') {
          cascadeQueries.slice(0, 2).forEach(q => {
            cascadePromises.push(searchRemoteOK(q));
            cascadePromises.push(searchArbeitnow(q));
          });
        }
        const cascadeResults = await Promise.allSettled(cascadePromises);
        for (const r of cascadeResults) {
          if (r.status === 'fulfilled') {
            for (const j of r.value) {
              const key = deduplicationKey(j);
              if (!seen.has(key) && !existingKeys.includes(key)) {
                seen.set(key, deduped.length);
                deduped.push(j);
              }
            }
          }
        }
      }
      console.log(`[Search] After cascade: ${deduped.length} total jobs`);
    }

    /* ---- DATE FRESHNESS FILTER — reject jobs older than 30 days ---- */
    const now = Date.now();
    const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
    const dateFresh = deduped.filter(j => {
      if (!j.datePosted) return true;
      const posted = new Date(j.datePosted).getTime();
      if (isNaN(posted)) return true;
      return (now - posted) <= MAX_AGE_MS;
    });
    console.log(`[Search] After date filter: ${dateFresh.length} (removed ${deduped.length - dateFresh.length} old jobs)`);

    /* ---- STRICT LOCATION FILTERING — only show jobs matching user-selected locations ---- */
    const METRO_EXPANSION = {
      'hyderabad': ['hyderabad','hyd','hitec city','hi-tech city','gachibowli','madhapur','kondapur','kukatpally','secunderabad','uppal','ameerpet','begumpet','miyapur','lb nagar','jubilee hills','banjara hills'],
      'bangalore': ['bangalore','bengaluru','blr','electronic city','whitefield','marathahalli','koramangala','hsr layout','manyata','hebbal','bellandur','sarjapur','jp nagar','indiranagar'],
      'bengaluru': ['bangalore','bengaluru','blr','electronic city','whitefield','marathahalli','koramangala','hsr layout','manyata','hebbal','bellandur','sarjapur','jp nagar','indiranagar'],
      'mumbai': ['mumbai','bom','navi mumbai','thane','andheri','bkc','powai','lower parel','goregaon','malad','worli','dadar','borivali'],
      'delhi': ['delhi','new delhi','del','delhi ncr','ncr'],
      'delhi ncr': ['delhi','new delhi','del','delhi ncr','ncr','noida','greater noida','gurugram','gurgaon','faridabad','ghaziabad'],
      'noida': ['noida','greater noida'],
      'gurugram': ['gurugram','gurgaon'],
      'gurgaon': ['gurugram','gurgaon'],
      'pune': ['pune','hinjewadi','kharadi','magarpatta','wakad','baner','viman nagar','hadapsar','aundh'],
      'chennai': ['chennai','omr','sholinganallur','tambaram','porur','guindy','taramani','velachery','adyar'],
      'kolkata': ['kolkata','salt lake','rajarhat','new town'],
      'ahmedabad': ['ahmedabad','gandhinagar'],
      'jaipur': ['jaipur'],
      'lucknow': ['lucknow'],
      'kochi': ['kochi','ernakulam'],
      'indore': ['indore'],
      'chandigarh': ['chandigarh','mohali','panchkula'],
      'visakhapatnam': ['visakhapatnam','vizag','vishakhapatnam'],
      'vizag': ['visakhapatnam','vizag','vishakhapatnam'],
      'coimbatore': ['coimbatore'],
      'thiruvananthapuram': ['thiruvananthapuram','trivandrum'],
    };

    function normalizeLocation(loc) {
      return loc.toLowerCase()
        .replace(/,\s*(india|in)$/i, '')
        .replace(/,\s*(telangana|karnataka|maharashtra|tamil nadu|andhra pradesh|west bengal|uttar pradesh|haryana|rajasthan|gujarat|kerala|madhya pradesh|odisha|bihar|jharkhand|punjab|chandigarh|uttarakhand|puducherry|goa)\s*$/i, '')
        .trim();
    }

    const selectedLocations = (profile.selectedLocations || (location ? location.split(',').map(s => s.trim()).filter(Boolean) : []));
    const locLower = selectedLocations.map(l => l.toLowerCase().trim());
    const hasLocFilter = locLower.length > 0 && !locLower.includes('all locations');
    const wantsRemote = locLower.includes('remote');
    const physicalLocs = locLower.filter(l => l !== 'remote' && l !== 'all locations');

    const expandedLocs = new Set();
    for (const loc of physicalLocs) {
      const normLoc = normalizeLocation(loc);
      expandedLocs.add(normLoc);
      const expanded = METRO_EXPANSION[normLoc];
      if (expanded) expanded.forEach(a => expandedLocs.add(a));
    }

    let locationFiltered = dateFresh;
    if (hasLocFilter) {
      locationFiltered = dateFresh.filter(j => {
        const rawJobLoc = (j.location || '').toLowerCase();
        const normJobLoc = normalizeLocation(rawJobLoc);
        const jobIsRemote = j.isRemote || /\bremote\b/i.test(rawJobLoc);

        if (wantsRemote && physicalLocs.length === 0) {
          return jobIsRemote;
        }

        if (physicalLocs.length > 0) {
          const locMatch = [...expandedLocs].some(loc => normJobLoc.includes(loc) || rawJobLoc.includes(loc));
          if (wantsRemote) {
            return locMatch || jobIsRemote;
          }
          return locMatch;
        }

        return true;
      });
      console.log(`[Search] After strict location filter: ${locationFiltered.length} (from ${dateFresh.length}, selected: ${selectedLocations.join(', ')})`);
    }

    /* ---- ROLE FILTERING ---- */
    const selectedRoles = profile.selectedRoles || (preferredRole ? [preferredRole] : []);
    const hasRoleFilter = selectedRoles.length > 0 && !selectedRoles.includes('Other');
    const roleFiltered = hasRoleFilter
      ? locationFiltered.filter(j => selectedRoles.some(role => jobMatchesPreferredRole(j.title, role)))
      : locationFiltered;

    function scoreAndTag(jobList) {
      return jobList
        .filter(j => validateJobData(j))
        .map(job => {
          const match = scoreJob(profile, job);
          if (!match) return null;
          return {
            ...job,
            score: match.score,
            titleMatchPct: match.titleMatchPct,
            skillMatchPct: match.skillMatchPct,
            confirmedRolePct: match.confirmedRolePct,
            experienceMatchPct: match.experienceMatchPct,
            projectMatchPct: match.projectMatchPct,
            domainMatchPct: match.domainMatchPct,
            matchingSkills: match.matchedSkills,
            missingSkills: match.missingSkills,
            matchedRole: match.matchedRole || '',
            domain: match.domain,
            recommendationReason:
              match.confirmedRolePct >= 80 && match.skillMatchPct >= 50
                ? 'Strong role and skill alignment'
                : match.confirmedRolePct >= 60
                  ? `Matches confirmed role: ${match.matchedRole || 'your preference'}`
                  : `${match.skillMatchPct}% JD skill match`
          };
        }).filter(Boolean).sort((a, b) => b.score - a.score);
    }

    const scored = scoreAndTag(roleFiltered);

    let finalJobs = scored;
    let fallbackUsed = '';

    console.log(`[Search] Jobs fetched: ${allRaw.length}`);
    console.log(`[Search] After dedup: ${deduped.length}`);
    console.log(`[Search] After location filter: ${locationFiltered.length}`);
    console.log(`[Search] After title/role filter: ${roleFiltered.length}`);
    console.log(`[Search] After scoring: ${scored.length}`);
    if (roleFiltered.length === 0 && locationFiltered.length > 0) {
      const sampleTitles = locationFiltered.slice(0, 5).map(j => j.title);
      console.log(`[Search] All ${locationFiltered.length} jobs rejected by role filter. Sample titles:`, sampleTitles);
      console.log(`[Search] Selected roles:`, selectedRoles);
    }
    if (scored.length === 0 && roleFiltered.length > 0) {
      const sampleScores = roleFiltered.slice(0, 3).map(j => ({ title: j.title, sim: selectedRoles.map(r => roleTitleSimilarity(j.title, r)) }));
      console.log(`[Search] All ${roleFiltered.length} role-matched jobs rejected by scoring. Samples:`, JSON.stringify(sampleScores));
    }

    /* ---- EXPANSION ROUND: if < 5 results, search ALL sources with expanded titles ---- */
    if (finalJobs.length < 5 && selectedRoles.length > 0) {
      console.log(`[Search] Only ${finalJobs.length} jobs — running expansion round (all sources)`);
      const expandedTitles = getExpandedQueries(selectedRoles);
      const expansionQueries = expandedTitles.filter(q => !queries.includes(q)).slice(0, 8);

      if (expansionQueries.length > 0) {
        const expPromises = [];
        const expLabels = [];
        for (const q of expansionQueries) {
          expPromises.push(searchJSearch(q, location));
          expLabels.push('JSearch');
          expPromises.push(searchAdzuna(q, location));
          expLabels.push('Adzuna');
          expPromises.push(searchJooble(q, location));
          expLabels.push('Jooble');
          expPromises.push(searchArbeitnow(q));
          expLabels.push('Arbeitnow');
          expPromises.push(searchRemoteOK(q));
          expLabels.push('RemoteOK');
          expPromises.push(searchTheMuse(q, location));
          expLabels.push('TheMuse');
        }
        // ATS boards with expanded queries
        expPromises.push(searchGreenhouse(expansionQueries, candidateDomain));
        expLabels.push('Greenhouse');
        expPromises.push(searchLever(expansionQueries, candidateDomain));
        expLabels.push('Lever');
        expPromises.push(searchSmartRecruiters(expansionQueries, candidateDomain));
        expLabels.push('SmartRecruiters');
        expPromises.push(searchAshby(expansionQueries, candidateDomain));
        expLabels.push('Ashby');
        expPromises.push(searchWorkday(expansionQueries, candidateDomain, location));
        expLabels.push('Workday');
        const expResults = await Promise.allSettled(expPromises);
        const expRaw = [];
        for (let i = 0; i < expResults.length; i++) {
          if (expResults[i].status === 'fulfilled') {
            expRaw.push(...expResults[i].value);
            const label = expLabels[i];
            sourceCounts[label] = (sourceCounts[label] || 0) + expResults[i].value.length;
          }
        }
        const existingSeen = new Set([...seen]);
        const newJobs = expRaw.filter(j => {
          const k = deduplicationKey(j);
          if (existingSeen.has(k) || existingKeys.includes(k)) return false;
          existingSeen.add(k);
          return true;
        });

        if (newJobs.length > 0) {
          let freshNew = newJobs.filter(j => { if (!j.datePosted) return true; const p = new Date(j.datePosted).getTime(); return isNaN(p) || (now - p) <= MAX_AGE_MS; });
          if (hasLocFilter) {
            freshNew = freshNew.filter(j => {
              const rawJobLoc = (j.location || '').toLowerCase();
              const normJobLoc = normalizeLocation(rawJobLoc);
              const jobIsRemote = j.isRemote || /\bremote\b/i.test(rawJobLoc);
              if (wantsRemote && physicalLocs.length === 0) return jobIsRemote;
              if (physicalLocs.length > 0) {
                const locMatch = [...expandedLocs].some(loc => normJobLoc.includes(loc) || rawJobLoc.includes(loc));
                return wantsRemote ? (locMatch || jobIsRemote) : locMatch;
              }
              return true;
            });
          }
          const expandedScored = scoreAndTag(freshNew);
          finalJobs = [...finalJobs, ...expandedScored].sort((a, b) => b.score - a.score);
          if (expandedScored.length > 0) fallbackUsed = fallbackUsed || 'expanded';
          console.log(`[Search] Expansion: ${expRaw.length} raw → ${newJobs.length} new → ${freshNew.length} loc-filtered → ${expandedScored.length} scored`);
        }
      }

      /* ---- EXPANSION CASCADE: if still < 3, try expanded titles with broader search ---- */
      if (finalJobs.length < 3 && location && location !== 'Remote') {
        console.log(`[Search] Still only ${finalJobs.length} — expansion cascade with broader search`);
        const expTitles = expandedTitles.slice(0, 4);
        const broadLocs = ['India', 'Remote'];
        for (const bLoc of broadLocs) {
          if (finalJobs.length >= 3) break;
          const bcPromises = expTitles.flatMap(q => [
            searchJSearch(q, bLoc),
            searchAdzuna(q, bLoc),
          ]);
          const bcResults = await Promise.allSettled(bcPromises);
          const bcRaw = [];
          for (const r of bcResults) {
            if (r.status === 'fulfilled') bcRaw.push(...r.value);
          }
          const bcNew = bcRaw.filter(j => {
            const k = deduplicationKey(j);
            if (seen.has(k) || existingKeys.includes(k)) return false;
            seen.set(k, -1);
            return true;
          });
          if (bcNew.length > 0) {
            let bcFiltered = bcNew.filter(j => { if (!j.datePosted) return true; const p = new Date(j.datePosted).getTime(); return isNaN(p) || (now - p) <= MAX_AGE_MS; });
            if (hasLocFilter) {
              bcFiltered = bcFiltered.filter(j => {
                const rawJobLoc = (j.location || '').toLowerCase();
                const normJobLoc = normalizeLocation(rawJobLoc);
                const jobIsRemote = j.isRemote || /\bremote\b/i.test(rawJobLoc);
                if (wantsRemote && physicalLocs.length === 0) return jobIsRemote;
                if (physicalLocs.length > 0) {
                  const locMatch = [...expandedLocs].some(loc => normJobLoc.includes(loc) || rawJobLoc.includes(loc));
                  return wantsRemote ? (locMatch || jobIsRemote) : locMatch;
                }
                return true;
              });
            }
            const bcScored = scoreAndTag(bcFiltered);
            finalJobs = [...finalJobs, ...bcScored].sort((a, b) => b.score - a.score);
            if (bcScored.length > 0) fallbackUsed = fallbackUsed || 'expanded-cascade';
            console.log(`[Search] Expansion cascade (${bLoc}): ${bcRaw.length} raw → ${bcNew.length} new → ${bcFiltered.length} loc-filtered → ${bcScored.length} scored`);
          }
        }
      }
    }

    if (finalJobs.length === 0 && roleFiltered.length > 0) {
      finalJobs = scoreAndTag(roleFiltered);
      fallbackUsed = finalJobs.length > 0 ? 'role-filtered' : '';
      console.log(`[Search] Fallback → ${finalJobs.length} role-filtered jobs passed scoring`);
    }

    if (finalJobs.length === 0 && locationFiltered.length > 0) {
      const fallbackScored = scoreAndTag(locationFiltered).filter(j => j.score >= 30);
      if (fallbackScored.length > 0) {
        finalJobs = fallbackScored;
        fallbackUsed = 'related';
        console.log(`[Search] Fallback → ${fallbackScored.length} related jobs with score >= 30`);
      }
    }

    /* ---- Location filter is strict — never show jobs from unselected locations ---- */

    const top = finalJobs.slice(0, 25);

    const validated = [];
    const validationBatch = top.slice(0, 20);
    const validationResults = await Promise.allSettled(
      validationBatch.map(j => validateLink(j.applyLink, 3500))
    );

    for (let i = 0; i < validationBatch.length; i++) {
      const isValid = validationResults[i].status === 'fulfilled' && validationResults[i].value;
      validationBatch[i].verified = !!isValid;
      validated.push(validationBatch[i]);
    }

    if (validated.length > 0) setCache(cacheKey, validated);

    const activeSources = Object.entries(sourceCounts).filter(([, c]) => c > 0).map(([s]) => s);
    let summary;
    if (validated.length > 0 && !fallbackUsed) {
      summary = `Found ${validated.length} matching job${validated.length === 1 ? '' : 's'} for "${preferredRole || 'your profile'}" from ${activeSources.join(', ')}.`;
    } else if (validated.length > 0 && fallbackUsed === 'expanded') {
      summary = `Found ${validated.length} job${validated.length === 1 ? '' : 's'} after searching ${queries.length}+ title variations across ${activeSources.join(', ')}.`;
    } else if (validated.length > 0 && fallbackUsed === 'expanded-cascade') {
      summary = `Found ${validated.length} job${validated.length === 1 ? '' : 's'} after exhaustive search across all title variations and broader locations.`;
    } else if (validated.length > 0 && fallbackUsed) {
      summary = `Showing ${validated.length} related job${validated.length === 1 ? '' : 's'} based on your preferred role. Exact matches were limited.`;
    } else {
      summary = `All ${activeSources.length || 5} job sources were searched exhaustively with ${queries.length} queries, location fallbacks, and ${Object.keys(RELATED_TITLES).length > 0 ? 'title expansion' : 'related titles'}. No verified openings matched. Please try different roles, another location, or search again later.`;
    }

    console.log(`[Search] Final: ${validated.length} jobs | Fallback: ${fallbackUsed || 'none'} | Role: ${preferredRole || 'any'} | Sources: ${JSON.stringify(sourceCounts)}`);

    res.json({
      jobs: validated.slice(0, 20),
      source: 'live',
      summary,
      fallbackUsed: fallbackUsed || null,
      apiStatus,
      sourceCounts,
      totalRaw: allRaw.length,
      totalDeduped: deduped.length,
      totalRoleFiltered: roleFiltered.length,
      totalScored: scored.length,
      queries
    });
  } catch (err) {
    console.error('[Search] Fatal error:', err);
    res.status(500).json({ error: 'Search failed: ' + err.message, jobs: [], apiStatus });
  }
});

/* ================================================================
   SIMPLE SKILLS-ONLY SEARCH (public-style endpoint)
   POST /api/jobs/quick-search
   ================================================================ */
app.post('/api/jobs/quick-search', async (req, res) => {
  const { skills, location } = req.body;
  if (!skills || !skills.length) {
    return res.status(400).json({ error: 'At least one skill is required.' });
  }

  const profile = {
    skills,
    targetRoles: [],
    projects: [],
    experienceYears: 0,
    certifications: []
  };

  req.body.profile = profile;
  req.body.existingKeys = [];

  const queries = buildSearchQueries(profile);
  const cacheKey = 'quick|' + queries.slice().sort().join('|') + '|' + (location || 'any');
  const cached = getCached(cacheKey);
  if (cached) {
    return res.json({ jobs: cached.slice(0, 20), source: 'cache' });
  }

  try {
    const searchPromises = [];
    for (const q of queries) {
      searchPromises.push(searchJSearch(q, location));
      searchPromises.push(searchAdzuna(q, location));
      searchPromises.push(searchJooble(q, location));
      searchPromises.push(searchArbeitnow(q));
      searchPromises.push(searchRemoteOK(q));
    }

    const results = await Promise.allSettled(searchPromises);
    const allRaw = [];
    for (const r of results) {
      if (r.status === 'fulfilled') allRaw.push(...r.value);
    }

    const seen = new Set();
    const deduped = [];
    for (const j of allRaw) {
      const key = deduplicationKey(j);
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(j);
    }

    const scored = [];
    for (const job of deduped) {
      const match = scoreJob(profile, job);
      if (!match) continue;
      scored.push({ ...job, score: match.score, matchingSkills: match.matchedSkills, missingSkills: match.missingSkills });
    }

    scored.sort((a, b) => b.score - a.score);
    const top = scored.slice(0, 20);
    if (top.length > 0) setCache(cacheKey, top);

    res.json({ jobs: top, source: 'live' });
  } catch (err) {
    res.status(500).json({ error: err.message, jobs: [] });
  }
});

/* ================================================================
   AI RESUME ANALYSIS — Groq (primary) + Gemini (fallback)
   ================================================================ */
const groqKeys = getApiKeys('GROQ_API_KEY');
const groqClients = groqKeys.map(k => new Groq({ apiKey: k }));
const groqClient = groqClients.length > 0 ? groqClients[0] : null;

const RESUME_SYSTEM_PROMPT = `You are an expert resume analyzer for a job recommendation platform.

Read the resume completely from top to bottom.

Analysis Priority (STRICT ORDER):
1. Resume Summary / Career Objective (HIGHEST PRIORITY — if it mentions any role or domain, that DOMINATES everything else)
2. Skills Section (second highest — determine domain from the majority of domain-specific skills)
3. Projects (what domain do most projects belong to?)
4. Work Experience (what roles has the candidate held?)
5. Certifications (what domain are they certified in?)
6. Education (branch/specialization)

CRITICAL RULES:
- If the summary says "Aspiring VLSI Engineer" or "seeking Physical Design opportunities", the primaryDomain MUST be "VLSI" — even if the resume also lists Python, Java, Git, or other software skills.
- Generic skills (Python, C, Java, Git, Linux, MS Office, Communication) must NEVER override the dominant domain.
- If summary is unclear, determine domain from the MAJORITY of skills. Example: if 8 out of 10 skills are VLSI-related (Verilog, UVM, FPGA, etc.), the domain is VLSI — not "Software" just because Python is also listed.
- Only suggest preferredRoles that belong to the detected primaryDomain.
- Extract ALL technical skills mentioned in the resume.
- Calculate total experience in years from work history dates.

Return ONLY valid JSON. No markdown fences, no commentary.

Format:
{
  "primaryDomain": "",
  "candidateSummary": "",
  "preferredRoles": [],
  "skills": [],
  "experienceYears": 0,
  "certifications": [],
  "searchQueries": []
}`;

async function analyzeResumeWithGroq(resumeText) {
  if (groqClients.length === 0) return null;

  for (let i = 0; i < groqClients.length; i++) {
    try {
      const completion = await groqClients[i].chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: RESUME_SYSTEM_PROMPT },
          { role: 'user', content: resumeText.slice(0, 8000) }
        ],
        temperature: 0.1,
        response_format: { type: 'json_object' },
        max_tokens: 2048,
      });
      const content = completion.choices[0]?.message?.content;
      if (!content) continue;
      return JSON.parse(content);
    } catch (err) {
      const isRateErr = err.status === 429 || err.status === 402 || /rate.?limit|quota|too many/i.test(err.message);
      console.error(`[Groq] Key ${i} error:`, err.message);
      if (isRateErr && i < groqClients.length - 1) {
        console.log(`[Groq] Key ${i} rate-limited, trying key ${i + 1}`);
        continue;
      }
    }
  }
  return null;
}

async function analyzeResumeWithGemini(resumeText) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  try {
    const prompt = RESUME_SYSTEM_PROMPT + '\n\nResume Content:\n' + resumeText.slice(0, 8000);
    const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent';
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 2048 }
      })
    });
    if (!response.ok) return null;
    const data = await response.json();
    const parts = data.candidates?.[0]?.content?.parts || [];
    const rawText = parts.filter(p => p.text).map(p => p.text).join('\n');
    const startIdx = rawText.search(/[{[]/);
    if (startIdx === -1) return null;
    const openChar = rawText[startIdx];
    const closeChar = openChar === '{' ? '}' : ']';
    let depth = 0, inString = false, escapeNext = false;
    for (let i = startIdx; i < rawText.length; i++) {
      const ch = rawText[i];
      if (escapeNext) { escapeNext = false; continue; }
      if (ch === '\\' && inString) { escapeNext = true; continue; }
      if (ch === '"') { inString = !inString; continue; }
      if (inString) continue;
      if (ch === openChar) depth++;
      else if (ch === closeChar) { depth--; if (depth === 0) { try { return JSON.parse(rawText.slice(startIdx, i + 1)); } catch { return null; } } }
    }
    return null;
  } catch (err) {
    console.error('[Gemini] Error:', err.message);
    return null;
  }
}

app.post('/api/resume/analyze', async (req, res) => {
  const { resumeText } = req.body;

  if (!resumeText || resumeText.trim().length < 50) {
    return res.status(400).json({ error: 'Resume text is too short or missing.' });
  }

  let parsed = null;
  let provider = '';

  if (groqClient) {
    console.log('[Resume] Analyzing with Groq (llama-3.3-70b)...');
    parsed = await analyzeResumeWithGroq(resumeText);
    if (parsed) provider = 'groq';
  }

  if (!parsed && process.env.GEMINI_API_KEY) {
    console.log('[Resume] Groq unavailable, falling back to Gemini...');
    parsed = await analyzeResumeWithGemini(resumeText);
    if (parsed) provider = 'gemini';
  }

  if (!parsed) {
    return res.status(200).json({ fallback: true, error: 'AI analysis unavailable — using local parsing.' });
  }

  console.log(`[Resume] Analysis complete via ${provider}:`, JSON.stringify({
    domain: parsed.primaryDomain,
    roles: parsed.preferredRoles?.slice(0, 3),
    skills: parsed.skills?.length,
    exp: parsed.experienceYears,
  }));

  res.json({
    provider,
    analysis: {
      primaryDomain: parsed.primaryDomain || '',
      candidateSummary: parsed.candidateSummary || '',
      skills: parsed.skills || [],
      preferredRoles: (parsed.preferredRoles || []).slice(0, 10),
      experienceYears: parsed.experienceYears || 0,
      certifications: parsed.certifications || [],
      recommendedRoles: (parsed.preferredRoles || []).map(r => ({ role: r, matchScore: 90, reason: 'AI-detected from resume', jobSearchQuery: r })),
      searchQueries: (parsed.searchQueries || parsed.preferredRoles || []).slice(0, 6),
    }
  });
});

/* ================================================================
   API STATUS ENDPOINT
   ================================================================ */
app.get('/api/roles', (req, res) => {
  res.json({ roles: Object.keys(ROLE_ALIASES) });
});

app.get('/api/health', (req, res) => {
  const snapshot = getHealthSnapshot();
  const sorted = ALL_SOURCES
    .map(s => ({ source: s, ...snapshot[s] }))
    .sort((a, b) => b.score - a.score);
  res.json({
    sources: snapshot,
    ranked: sorted.map(s => `${s.source} (score:${s.score}, success:${s.successRate}%, avg:${s.averageResponseTime}ms${s.rateLimited ? ' [COOLED DOWN]' : ''})`),
    cooldowns: Object.fromEntries([...rateLimitCooldowns].map(([k, v]) => [k, { until: new Date(v).toISOString(), remainingMs: Math.max(0, v - Date.now()) }])),
    timestamp: new Date().toISOString()
  });
});

app.get('/api/status', (req, res) => {
  const apis = {
    jsearch: !!(process.env.JSEARCH_API_KEY && !process.env.JSEARCH_API_KEY.startsWith('your_')),
    adzuna: !!(process.env.ADZUNA_APP_ID && !process.env.ADZUNA_APP_ID.startsWith('your_') && process.env.ADZUNA_API_KEY && !process.env.ADZUNA_API_KEY.startsWith('your_')),
    jooble: !!(process.env.JOOBLE_API_KEY && !process.env.JOOBLE_API_KEY.startsWith('your_')),
    arbeitnow: true,
    remoteok: true,
    themuse: true,
    greenhouse: true,
    lever: true,
    smartrecruiters: true,
    ashby: true,
    workday: true,
    groq: !!groqClient,
    gemini: !!(process.env.GEMINI_API_KEY && !process.env.GEMINI_API_KEY.startsWith('your_')),
  };
  const active = Object.entries(apis).filter(([, v]) => v).map(([k]) => k);
  res.json({ apis, activeCount: active.length, active });
});

/* ================================================================
   DAILY JOB REFRESH — midnight archival
   ================================================================ */
function todayDateStr() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

app.post('/api/jobs/archive', (req, res) => {
  const today = todayDateStr();
  try {
    const allUsers = db.prepare('SELECT DISTINCT user_id FROM user_data WHERE data_key = ?').all('jobs');
    let archived = 0;

    for (const { user_id } of allUsers) {
      const row = stmts.getData.get(user_id, 'jobs');
      if (!row) continue;

      let jobs;
      try { jobs = JSON.parse(row.data_json); } catch { continue; }
      if (!Array.isArray(jobs) || jobs.length === 0) continue;

      const todaysJobs = jobs.filter(j => j.dateAdded === today);
      const olderJobs = jobs.filter(j => j.dateAdded !== today);

      if (olderJobs.length === 0) continue;

      olderJobs.forEach(j => { j.category = 'previous'; });
      todaysJobs.forEach(j => { j.category = 'today'; });

      stmts.upsertData.run(user_id, 'jobs', JSON.stringify([...todaysJobs, ...olderJobs]));
      archived += olderJobs.length;
    }

    jobCache.clear();

    console.log(`[Archive] ${archived} jobs archived across ${allUsers.length} users on ${today}`);
    res.json({ ok: true, archived, date: today });
  } catch (err) {
    console.error('[Archive] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/server-date', (req, res) => {
  res.json({ date: todayDateStr(), iso: new Date().toISOString() });
});

function scheduleMidnightRefresh() {
  const now = new Date();
  const midnight = new Date(now);
  midnight.setHours(24, 0, 0, 0);
  const msUntilMidnight = midnight.getTime() - now.getTime();

  console.log(`  Next midnight refresh in ${Math.round(msUntilMidnight / 60000)} minutes`);

  setTimeout(() => {
    runMidnightArchive();
    setInterval(runMidnightArchive, 24 * 60 * 60 * 1000);
  }, msUntilMidnight);
}

function runMidnightArchive() {
  const today = todayDateStr();
  console.log(`\n[Midnight] Running daily archive — ${today}`);

  try {
    const allUsers = db.prepare('SELECT DISTINCT user_id FROM user_data WHERE data_key = ?').all('jobs');
    let totalArchived = 0;

    for (const { user_id } of allUsers) {
      const row = stmts.getData.get(user_id, 'jobs');
      if (!row) continue;

      let jobs;
      try { jobs = JSON.parse(row.data_json); } catch { continue; }
      if (!Array.isArray(jobs) || jobs.length === 0) continue;

      jobs.forEach(j => {
        if (j.dateAdded !== today) {
          j.category = 'previous';
        }
      });

      stmts.upsertData.run(user_id, 'jobs', JSON.stringify(jobs));
      totalArchived += jobs.filter(j => j.category === 'previous').length;
    }

    jobCache.clear();
    console.log(`[Midnight] Archived ${totalArchived} jobs. Cache cleared. Ready for new day.\n`);
  } catch (err) {
    console.error('[Midnight] Archive error:', err.message);
  }
}

/* ================================================================
   START SERVER
   ================================================================ */
app.listen(PORT, () => {
  console.log(`\n  CareerAI server running at http://localhost:${PORT}\n`);

  const apis = [];
  if (process.env.JSEARCH_API_KEY && !process.env.JSEARCH_API_KEY.startsWith('your_')) apis.push('JSearch');
  if (process.env.ADZUNA_APP_ID && process.env.ADZUNA_API_KEY && !process.env.ADZUNA_API_KEY.startsWith('your_')) apis.push('Adzuna');
  if (process.env.JOOBLE_API_KEY && !process.env.JOOBLE_API_KEY.startsWith('your_')) apis.push('Jooble');
  apis.push('Arbeitnow (free)');
  apis.push('RemoteOK (free)');
  apis.push('The Muse (free)');
  apis.push('Greenhouse ATS (free)');
  apis.push('Lever ATS (free)');
  apis.push('SmartRecruiters (free)');
  apis.push('Ashby (free)');
  apis.push('Workday (free)');
  if (groqClient) apis.push('Groq AI (primary)');
  if (process.env.GEMINI_API_KEY) apis.push('Gemini AI (fallback)');

  console.log(`  Active APIs: ${apis.join(', ')}`);
  console.log(`  Cache TTL: ${CACHE_TTL / 60000} minutes`);

  scheduleMidnightRefresh();

  if (!process.env.JWT_SECRET) console.warn('  WARNING: JWT_SECRET not set — using insecure default.');
  console.log('');
});
