const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
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
const db = new Database(path.join(__dirname, 'careerai.db'));
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

function scoreJob(profile, job) {
  const userSkills = new Set((profile.skills || []).map(s => s.toLowerCase()));
  const jobSkills = (job.skills || []).map(s => s.toLowerCase());
  if (jobSkills.length === 0) return null;

  const matched = jobSkills.filter(s => userSkills.has(s));
  const missing = jobSkills.filter(s => !userSkills.has(s));
  const skillPct = (matched.length / jobSkills.length) * 100;

  let projPct = 0;
  if (profile.projects && profile.projects.length > 0) {
    const projTech = new Set(profile.projects.flatMap(p => (p.tech || '').split(/[,;]/).map(t => t.trim().toLowerCase())).filter(Boolean));
    const projOverlap = jobSkills.filter(s => projTech.has(s));
    projPct = (projOverlap.length / jobSkills.length) * 100;
  }

  const userDomain = detectDomain(profile.skills || []);
  const jobDomain = detectDomain(job.skills || []);
  let domainPct = userDomain === jobDomain ? 100 : 0;
  if (domainPct === 0) {
    const domSkills = DOMAIN_SKILL_MAP[jobDomain] || [];
    const overlap = domSkills.filter(s => userSkills.has(s.toLowerCase())).length;
    domainPct = domSkills.length > 0 ? Math.min((overlap / domSkills.length) * 100, 50) : 0;
  }

  let score = (0.70 * skillPct) + (0.20 * projPct) + (0.10 * domainPct);
  if (profile.experienceYears > 0) score += Math.min(profile.experienceYears, 3);
  if ((profile.certifications || []).length > 0) score += Math.min(profile.certifications.length * 1.5, 5);
  score = Math.round(Math.min(score, 100));

  if (skillPct < 10) return null;
  if (score < 15) return null;

  return {
    score,
    skillMatchPct: Math.round(skillPct),
    projectMatchPct: Math.round(projPct),
    domainMatchPct: Math.round(domainPct),
    matchedSkills: matched.map(s => job.skills.find(js => js.toLowerCase() === s) || s),
    missingSkills: missing.map(s => job.skills.find(js => js.toLowerCase() === s) || s),
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
  'VLSI Engineer': ['vlsi','rtl design','physical design','dft engineer','verification engineer','asic','fpga','chip design','sta engineer','layout engineer','analog design','digital design','verilog','vhdl'],
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
  const aliases = ROLE_ALIASES[preferredRole];
  if (!aliases) return true;
  const titleLower = jobTitle.toLowerCase();
  return aliases.some(alias => titleLower.includes(alias));
}

/* ================================================================
   BUILD SEARCH QUERIES FROM PROFILE
   ================================================================ */
function buildSearchQueries(profile) {
  const queries = [];
  const preferredRole = profile.preferredRole;

  if (preferredRole && preferredRole !== 'Other') {
    queries.push(preferredRole);
    const aliases = ROLE_ALIASES[preferredRole];
    if (aliases) {
      aliases.slice(0, 3).forEach(a => {
        if (a.toLowerCase() !== preferredRole.toLowerCase()) queries.push(a);
      });
    }
  }

  if (profile.aiSearchQueries && profile.aiSearchQueries.length > 0 && queries.length < 4) {
    profile.aiSearchQueries.slice(0, 2).forEach(q => queries.push(q));
  }

  if (queries.length === 0) {
    const roles = profile.targetRoles || [];
    const skills = profile.skills || [];
    const domain = detectDomain(skills);
    if (roles.length > 0) roles.slice(0, 3).forEach(r => queries.push(r));
    if (domain !== 'General') queries.push(domain + ' engineer');
    const topSkills = skills.slice(0, 4);
    if (topSkills.length >= 2) queries.push(topSkills.slice(0, 3).join(' ') + ' developer');
    if (queries.length === 0) queries.push(skills.slice(0, 3).join(' ') + ' jobs');
  }

  return [...new Set(queries)].slice(0, 6);
}

/* ================================================================
   API SOURCE 1: JSEARCH (RapidAPI)
   ================================================================ */
async function searchJSearch(query, location) {
  const apiKey = process.env.JSEARCH_API_KEY;
  if (!apiKey || apiKey.startsWith('your_')) return [];

  const params = new URLSearchParams({
    query: `${query} in ${location || 'India'}`,
    num_pages: '1',
    date_posted: 'month',
    country: 'in'
  });

  try {
    const res = await fetch(`https://jsearch.p.rapidapi.com/search-v2?${params}`, {
      headers: {
        'x-rapidapi-key': apiKey,
        'x-rapidapi-host': 'jsearch.p.rapidapi.com'
      }
    });

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
      source: 'jsearch'
    })).filter(j => j.company && j.title && j.applyLink);
  } catch (e) {
    console.error('[JSearch] Error:', e.message);
    return [];
  }
}

/* ================================================================
   API SOURCE 2: ADZUNA
   ================================================================ */
async function searchAdzuna(query, location) {
  const appId = process.env.ADZUNA_APP_ID;
  const apiKey = process.env.ADZUNA_API_KEY;
  if (!appId || appId.startsWith('your_') || !apiKey || apiKey.startsWith('your_')) return [];

  const params = new URLSearchParams({
    app_id: appId,
    app_key: apiKey,
    results_per_page: '20',
    what: query,
    where: location || 'India',
    max_days_old: '30',
    sort_by: 'relevance',
    content_type: 'application/json'
  });

  try {
    const res = await fetch(`https://api.adzuna.com/v1/api/jobs/in/search/1?${params}`);
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
      source: 'adzuna'
    })).filter(j => j.company && j.title && j.applyLink);
  } catch (e) {
    console.error('[Adzuna] Error:', e.message);
    return [];
  }
}

/* ================================================================
   API SOURCE 3: ARBEITNOW (free, no key required)
   ================================================================ */
async function searchArbeitnow(query) {
  try {
    const res = await fetch('https://www.arbeitnow.com/api/job-board-api', {
      headers: { 'Accept': 'application/json' }
    });
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
  try {
    const tag = query.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
    const res = await fetch(`https://remoteok.com/api?tag=${tag}`, {
      headers: { 'User-Agent': 'CareerAI/2.0' }
    });
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
  try {
    const params = new URLSearchParams({ page: '0', descending: 'true' });
    if (location) params.set('location', location);

    const res = await fetch(`https://www.themuse.com/api/public/jobs?${params}`, {
      headers: { 'Accept': 'application/json' }
    });
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
   ================================================================ */
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
      searchPromises.push(searchJSearch(q, location));
      sourceLabels.push('JSearch');

      searchPromises.push(searchAdzuna(q, location));
      sourceLabels.push('Adzuna');

      searchPromises.push(searchArbeitnow(q));
      sourceLabels.push('Arbeitnow');

      searchPromises.push(searchRemoteOK(q));
      sourceLabels.push('RemoteOK');

      searchPromises.push(searchTheMuse(q, location));
      sourceLabels.push('TheMuse');
    }

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

    const seen = new Set();
    const deduped = [];
    for (const j of allRaw) {
      const key = deduplicationKey(j);
      if (seen.has(key)) continue;
      if (existingKeys.includes(key)) continue;
      seen.add(key);
      deduped.push(j);
    }

    const roleFiltered = preferredRole && preferredRole !== 'Other'
      ? deduped.filter(j => jobMatchesPreferredRole(j.title, preferredRole))
      : deduped;

    function scoreAndTag(jobList) {
      return jobList.map(job => {
        const match = scoreJob(profile, job);
        const s = match ? match.score : 0;
        return {
          ...job,
          score: s,
          skillMatchPct: match ? match.skillMatchPct : 0,
          projectMatchPct: match ? match.projectMatchPct : 0,
          domainMatchPct: match ? match.domainMatchPct : 0,
          matchingSkills: match ? match.matchedSkills : [],
          missingSkills: match ? match.missingSkills : [],
          domain: match ? match.domain : '',
          recommendationReason: match
            ? (match.skillMatchPct >= 70 ? 'Strong skill alignment' : `${match.skillMatchPct}% skill match`)
            : 'Role match'
        };
      }).sort((a, b) => b.score - a.score);
    }

    const scored = scoreAndTag(roleFiltered).filter(j => j.score > 0);

    let finalJobs = scored;
    let fallbackUsed = '';

    console.log(`[Search] Fetched jobs: ${allRaw.length}`);
    console.log(`[Search] After dedup: ${deduped.length}`);
    console.log(`[Search] After role filter: ${roleFiltered.length}`);
    console.log(`[Search] After skill match: ${scored.length}`);

    if (scored.length === 0 && roleFiltered.length > 0) {
      finalJobs = scoreAndTag(roleFiltered);
      fallbackUsed = 'role-filtered';
      console.log(`[Search] Fallback → using ${roleFiltered.length} role-filtered jobs (no skill threshold)`);
    }

    if (finalJobs.length === 0 && deduped.length > 0) {
      finalJobs = scoreAndTag(deduped);
      fallbackUsed = 'all-deduped';
      console.log(`[Search] Fallback → using all ${deduped.length} deduped jobs`);
    }

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
    } else if (validated.length > 0 && fallbackUsed) {
      summary = `Showing ${validated.length} related job${validated.length === 1 ? '' : 's'} based on your preferred role. Exact skill matches were limited.`;
    } else {
      summary = 'No jobs returned from APIs. Please try a different role or location.';
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
   AI RESUME ANALYSIS (Gemini)
   ================================================================ */
const RESUME_ANALYSIS_PROMPT = `You are an AI Resume-to-Job Matching Engine.

Your task is to analyze the candidate's resume and identify the most suitable REAL job roles available in today's market.

Instructions:
1. Analyze the complete resume.
2. Extract technical skills, tools, frameworks, experience, and projects.
3. Recommend the TOP 5 most relevant job roles.
4. Generate optimized live job search queries for each role.
5. Only recommend jobs that the candidate is genuinely qualified for.
6. Prioritize roles with high hiring demand.
7. Return ONLY valid JSON — no markdown fences, no commentary.

Output format:
{
  "candidateSummary": "",
  "skills": [],
  "recommendedRoles": [
    {
      "role": "",
      "matchScore": 0,
      "reason": "",
      "jobSearchQuery": ""
    }
  ],
  "searchQueries": []
}

Rules:
- Use only skills found in the resume.
- Do not invent skills.
- Do not suggest unrelated roles.
- Generate search queries suitable for APIs like JSearch, Adzuna, Google Jobs, or LinkedIn Jobs.
- Example queries: "Backend Developer Python FastAPI AWS", "AI ML Engineer Python TensorFlow"

Resume Content:
`;

function extractJsonFromText(text) {
  const startIdx = text.search(/[{[]/);
  if (startIdx === -1) return null;
  const openChar = text[startIdx];
  const closeChar = openChar === '{' ? '}' : ']';
  let depth = 0, inString = false, escapeNext = false;
  for (let i = startIdx; i < text.length; i++) {
    const ch = text[i];
    if (escapeNext) { escapeNext = false; continue; }
    if (ch === '\\' && inString) { escapeNext = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === openChar) depth++;
    else if (ch === closeChar) {
      depth--;
      if (depth === 0) {
        try { return JSON.parse(text.slice(startIdx, i + 1)); } catch { return null; }
      }
    }
  }
  return null;
}

app.post('/api/resume/analyze', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  const { resumeText } = req.body;

  if (!resumeText || resumeText.trim().length < 50) {
    return res.status(400).json({ error: 'Resume text is too short or missing' });
  }

  if (!apiKey) {
    return res.status(200).json({ fallback: true, error: 'GEMINI_API_KEY not set — using local parsing only' });
  }

  try {
    const prompt = RESUME_ANALYSIS_PROMPT + resumeText.slice(0, 8000);
    const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent';
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 2048 }
      })
    });

    const data = await response.json();
    if (!response.ok) {
      const msg = data.error?.message || JSON.stringify(data).slice(0, 300);
      const isQuota = response.status === 429 || /quota|rate.?limit|resource.?exhaust/i.test(msg);
      return res.status(200).json({ fallback: isQuota, error: msg });
    }

    const parts = data.candidates?.[0]?.content?.parts || [];
    const rawText = parts.filter(p => p.text).map(p => p.text).join('\n');
    const parsed = extractJsonFromText(rawText);

    if (!parsed) {
      return res.status(200).json({ fallback: true, error: 'Could not parse AI response' });
    }

    res.json({
      analysis: {
        candidateSummary: parsed.candidateSummary || '',
        skills: parsed.skills || [],
        recommendedRoles: (parsed.recommendedRoles || []).slice(0, 5),
        searchQueries: (parsed.searchQueries || []).slice(0, 6)
      }
    });
  } catch (err) {
    console.error('[Resume Analysis] Error:', err.message);
    res.status(200).json({ fallback: true, error: err.message });
  }
});

/* ================================================================
   API STATUS ENDPOINT
   ================================================================ */
app.get('/api/roles', (req, res) => {
  res.json({ roles: Object.keys(ROLE_ALIASES) });
});

app.get('/api/status', (req, res) => {
  const apis = {
    jsearch: !!(process.env.JSEARCH_API_KEY && !process.env.JSEARCH_API_KEY.startsWith('your_')),
    adzuna: !!(process.env.ADZUNA_APP_ID && !process.env.ADZUNA_APP_ID.startsWith('your_') && process.env.ADZUNA_API_KEY && !process.env.ADZUNA_API_KEY.startsWith('your_')),
    arbeitnow: true,
    remoteok: true,
    themuse: true,
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
  apis.push('Arbeitnow (free)');
  apis.push('RemoteOK (free)');
  apis.push('The Muse (free)');
  if (process.env.GEMINI_API_KEY) apis.push('Gemini AI');

  console.log(`  Active APIs: ${apis.join(', ')}`);
  console.log(`  Cache TTL: ${CACHE_TTL / 60000} minutes`);

  scheduleMidnightRefresh();

  if (!process.env.JWT_SECRET) console.warn('  WARNING: JWT_SECRET not set — using insecure default.');
  console.log('');
});
