require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const seedQuestions = require('./seed-questions');
const expandedQuestions = require('./expanded-questions');

const app = express();
const port = Number(process.env.PORT || 10000);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false, options: '-c search_path=jua,public' });
const secret = process.env.JWT_SECRET;
const MIN_DEPOSIT = 200, MIN_STAKE = 50, MIN_WITHDRAWAL = 500, QUESTION_COUNT = 5;
if (!secret) throw new Error('JWT_SECRET is required');
app.use(helmet({ contentSecurityPolicy: false }));
app.post('/api/payments/webhook', express.raw({ type: 'application/json', limit: '50kb' }), async (req, res) => {
  try {
    const signature = String(req.headers['x-hashpay-signature'] || '');
    const secret = process.env.MOBILE_MONEY_WEBHOOK_SECRET;
    if (!secret || !validSignature(req.body, signature, secret)) return res.status(401).send('Invalid signature');
    const event = JSON.parse(req.body.toString('utf8'));
    if (event.event !== 'payment.success' || Number(event.ResponseCode) !== 0) return res.sendStatus(204);
    const reference = String(event.TransactionReference || ''), checkoutId = String(event.CheckoutRequestID || '');
    const amount = Number(event.TransactionAmount);
    const phone = cleanPhone(event.Msisdn);
    const { rows } = await pool.query("SELECT * FROM wallet_transactions WHERE (provider_checkout_id=$1 OR reference=$2) AND kind='deposit'", [checkoutId, reference]);
    const transaction = rows[0];
    if (!transaction || transaction.amount !== amount || transaction.phone !== phone) return res.status(400).send('Transaction does not match');
    if (transaction.provider_checkout_id && checkoutId && transaction.provider_checkout_id !== checkoutId) return res.status(400).send('Checkout does not match');
    if (transaction.status !== 'pending') return res.sendStatus(204);
    await confirmDeposit(transaction.id, String(event.TransactionID || event.TransactionReceipt || '') || null);
    res.sendStatus(204);
  } catch (error) { console.error('webhook failed', error.message); res.status(400).send('Invalid webhook'); }
});
app.use(express.json({ limit: '20kb' }));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/styles.css', (_req, res) => res.sendFile(path.join(__dirname, 'styles.css')));
app.get('/responsive.css', (_req, res) => res.sendFile(path.join(__dirname, 'responsive.css')));
app.get('/overrides.css', (_req, res) => res.sendFile(path.join(__dirname, 'overrides.css')));
app.get('/app.js', (_req, res) => res.sendFile(path.join(__dirname, 'app.js')));
app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/admin.js', (_req, res) => res.sendFile(path.join(__dirname, 'admin.js')));
app.get('/admin.css', (_req, res) => res.sendFile(path.join(__dirname, 'admin.css')));
app.get('/nairobi-kenya.png', (_req, res) => res.sendFile(path.join(__dirname, 'nairobi-kenya.png')));

const cleanPhone = (value) => {
  const digits = String(value || '').replace(/\D/g, '');
  const normalized = digits.startsWith('0') ? `254${digits.slice(1)}` : digits.startsWith('254') ? digits : `254${digits}`;
  if (!/^2547\d{8}$/.test(normalized)) throw new Error('Use a valid Kenyan mobile number.');
  return normalized;
};
const ref = (prefix) => `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
const tokenFor = (user) => jwt.sign({ sub: user.id, phone: user.phone }, secret, { expiresIn: '7d' });
const auth = async (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), secret); next(); }
  catch { res.status(401).json({ error: 'Please sign in to continue.' }); }
};
const number = (value, floor) => {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < floor) throw new Error(`Minimum amount is KES ${floor}.`);
  return parsed;
};
async function seed() {
  for (const [prompt, category, options, answer] of [...seedQuestions, ...expandedQuestions]) {
    await pool.query('INSERT INTO questions (prompt,category,options,answer_index) VALUES ($1,$2,$3,$4) ON CONFLICT (prompt) DO NOTHING', [prompt, category, JSON.stringify(options), answer]);
  }
}
app.get('/api/health', async (_req, res) => { await pool.query('SELECT 1'); res.json({ ok: true }); });
app.post('/api/auth/register', async (req, res) => {
  try {
    const phone = cleanPhone(req.body.phone), name = String(req.body.name || '').trim(), password = String(req.body.password || '');
    if (name.length < 2 || name.length > 40) throw new Error('Enter a display name of 2 to 40 characters.');
    if (password.length < 8) throw new Error('Choose a password with at least 8 characters.');
    if (req.body.acceptedTerms !== true) throw new Error('You must accept the Terms and Privacy Notice.');
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query('INSERT INTO users(phone,display_name,password_hash) VALUES($1,$2,$3) RETURNING id,phone,display_name,wallet_balance', [phone, name, hash]);
    const user = result.rows[0]; if (process.env.ADMIN_PHONE === phone) { user.role = 'admin'; await pool.query("UPDATE users SET role='admin' WHERE id=$1", [user.id]); } res.status(201).json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { res.status(error.code === '23505' ? 409 : 400).json({ error: error.code === '23505' ? 'An account already exists for this number. Please sign in.' : error.message }); }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const phone = cleanPhone(req.body.phone), result = await pool.query('SELECT * FROM users WHERE phone=$1', [phone]), user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Account does not exist. Please sign up.' });
    if (!(await bcrypt.compare(String(req.body.password || ''), user.password_hash))) return res.status(401).json({ error: 'Incorrect password. Please try again.' });
    res.json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});
app.get('/api/me', auth, async (req, res) => { const { rows } = await pool.query('SELECT id,phone,display_name,nickname,wallet_phone,wallet_balance,role FROM users WHERE id=$1', [req.user.sub]); res.json({ user: publicUser(rows[0]) }); });
app.patch('/api/profile', auth, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim(), nickname = String(req.body.nickname || '').trim(), phone = cleanPhone(req.body.phone), walletPhone = cleanPhone(req.body.walletPhone || phone);
    if (name.length < 2 || name.length > 40) throw new Error('Name must be 2 to 40 characters.');
    if (nickname && (nickname.length < 2 || nickname.length > 30)) throw new Error('Nickname must be 2 to 30 characters.');
    const { rows } = await pool.query('UPDATE users SET display_name=$1,nickname=$2,phone=$3,wallet_phone=$4 WHERE id=$5 RETURNING id,phone,display_name,nickname,wallet_phone,wallet_balance,role', [name, nickname || null, phone, walletPhone, req.user.sub]);
    res.json({ user: publicUser(rows[0]) });
  } catch (error) { res.status(error.code === '23505' ? 409 : 400).json({ error: error.code === '23505' ? 'That mobile number is already linked to another account.' : error.message }); }
});
app.post('/api/deposits', auth, async (req, res) => {
  try {
    const amount = number(req.body.amount, MIN_DEPOSIT), phone = cleanPhone(req.body.phone || req.user.phone), reference = ref('JUA');
    const created = await pool.query('INSERT INTO wallet_transactions(user_id,kind,amount,reference,phone) VALUES($1,$2,$3,$4,$5) RETURNING id', [req.user.sub, 'deposit', amount, reference, phone]);
    const providerResult = await mobileMoney('/initiatestk', { api_key: process.env.MOBILE_MONEY_API_KEY, account_id: process.env.MOBILE_MONEY_ACCOUNT_ID, amount: String(amount), msisdn: phone, reference });
    if (!providerResult.success || !providerResult.checkout_id) throw new Error(providerResult.message || 'Unable to start the mobile-money prompt.');
    await pool.query('UPDATE wallet_transactions SET provider_checkout_id=$1 WHERE id=$2', [providerResult.checkout_id, created.rows[0].id]);
    res.status(201).json({ id: created.rows[0].id, status: 'pending', message: 'Check your phone and enter your mobile-money PIN to complete the deposit.' });
  } catch (error) { res.status(400).json({ error: error.message }); }
});
app.get('/api/deposits/:id', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM wallet_transactions WHERE id=$1 AND user_id=$2 AND kind=$3', [req.params.id, req.user.sub, 'deposit']);
  const transaction = rows[0]; if (!transaction) return res.sendStatus(404);
  res.json({ status: transaction.status, amount: transaction.amount });
});
app.post('/api/withdrawals', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const amount = number(req.body.amount, MIN_WITHDRAWAL), phone = cleanPhone(req.body.phone);
    await client.query('BEGIN'); const user = await client.query('SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE', [req.user.sub]);
    if (!user.rows[0] || user.rows[0].wallet_balance < amount) throw new Error('Your available wallet balance is not enough for this withdrawal.');
    await client.query('UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2', [amount, req.user.sub]);
    await client.query('INSERT INTO wallet_transactions(user_id,kind,amount,reference,phone) VALUES($1,$2,$3,$4,$5)', [req.user.sub, 'withdrawal', amount, ref('WDR'), phone]); await client.query('COMMIT');
    res.status(201).json({ message: 'Your withdrawal request has been received.' });
  } catch (error) { await client.query('ROLLBACK'); res.status(400).json({ error: error.message }); } finally { client.release(); }
});
app.post('/api/games', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const stake = number(req.body.stake, MIN_STAKE); await client.query('BEGIN');
    const wallet = await client.query('SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE', [req.user.sub]);
    if (wallet.rows[0].wallet_balance < stake) throw new Error('Add money to JUA before you play this round.');
    const questions = await client.query(`SELECT id,prompt,category,options FROM questions q WHERE active AND NOT EXISTS (SELECT 1 FROM seen_questions s WHERE s.user_id=$1 AND s.question_id=q.id) ORDER BY random() LIMIT $2`, [req.user.sub, QUESTION_COUNT]);
    if (questions.rows.length < QUESTION_COUNT) throw new Error('You have completed every currently published question. More are being reviewed.');
    await client.query('UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2', [stake, req.user.sub]);
    const game = await client.query('INSERT INTO game_sessions(user_id,stake,question_ids) VALUES($1,$2,$3) RETURNING id,opponent_name', [req.user.sub, stake, JSON.stringify(questions.rows.map(q => q.id))]);
    await client.query('INSERT INTO seen_questions(user_id,question_id) SELECT $1, unnest($2::bigint[]) ON CONFLICT DO NOTHING', [req.user.sub, questions.rows.map(q => q.id)]);
    await client.query('COMMIT'); res.status(201).json({ game: game.rows[0], questions: questions.rows });
  } catch (error) { await client.query('ROLLBACK'); res.status(400).json({ error: error.message }); } finally { client.release(); }
});
app.post('/api/games/:id/submit', auth, async (req, res) => {
  const game = await pool.query('SELECT * FROM game_sessions WHERE id=$1 AND user_id=$2 AND status=$3', [req.params.id, req.user.sub, 'active']);
  if (!game.rows[0]) return res.status(404).json({ error: 'This game is no longer active.' });
  const ids = game.rows[0].question_ids, answers = Array.isArray(req.body.answers) ? req.body.answers : [];
  const keys = await pool.query('SELECT id,answer_index FROM questions WHERE id=ANY($1::bigint[])', [ids]);
  const score = keys.rows.reduce((total, question, index) => total + (Number(answers[index]) === question.answer_index ? 1 : 0), 0);
  const opponentScore = Math.max(0, Math.min(QUESTION_COUNT, score + (crypto.randomInt(3) - 1)));
  await pool.query('UPDATE game_sessions SET submitted_answers=$1,score=$2,status=$3,completed_at=NOW() WHERE id=$4', [JSON.stringify(answers), score, 'complete', game.rows[0].id]);
  res.json({ score, opponentScore, opponentName: game.rows[0].opponent_name, result: score > opponentScore ? 'win' : score === opponentScore ? 'draw' : 'loss' });
});
async function adminOnly(req, res, next) {
  const { rows } = await pool.query('SELECT role FROM users WHERE id=$1', [req.user.sub]);
  if (rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Administrator access is required.' });
  next();
}
app.get('/api/admin/overview', auth, adminOnly, async (_req, res) => {
  const [members, wallets, questions, withdrawals] = await Promise.all([
    pool.query('SELECT COUNT(*)::int AS count FROM users'),
    pool.query('SELECT COALESCE(SUM(wallet_balance),0)::int AS total FROM users'),
    pool.query('SELECT COUNT(*)::int AS count FROM questions WHERE active'),
    pool.query("SELECT COUNT(*)::int AS count FROM wallet_transactions WHERE kind='withdrawal' AND status='pending'")
  ]);
  res.json({ members: members.rows[0].count, walletBalance: wallets.rows[0].total, questions: questions.rows[0].count, pendingWithdrawals: withdrawals.rows[0].count });
});
app.get('/api/admin/members', auth, adminOnly, async (_req, res) => {
  const { rows } = await pool.query('SELECT id,display_name,phone,role,wallet_balance,created_at FROM users ORDER BY created_at DESC LIMIT 500');
  res.json({ members: rows.map(publicUserWithDate) });
});
app.get('/api/admin/withdrawals', auth, adminOnly, async (_req, res) => {
  const { rows } = await pool.query("SELECT t.id,t.amount,t.phone,t.status,t.reference,t.created_at,u.display_name FROM wallet_transactions t JOIN users u ON u.id=t.user_id WHERE t.kind='withdrawal' ORDER BY t.created_at DESC LIMIT 500");
  res.json({ withdrawals: rows });
});
app.patch('/api/admin/withdrawals/:id', auth, adminOnly, async (req, res) => {
  const allowed = ['processing', 'paid', 'rejected'];
  if (!allowed.includes(req.body.status)) return res.status(400).json({ error: 'Invalid withdrawal status.' });
  const { rows } = await pool.query("UPDATE wallet_transactions SET status=$1 WHERE id=$2 AND kind='withdrawal' RETURNING id,status", [req.body.status, req.params.id]);
  if (!rows[0]) return res.sendStatus(404); res.json(rows[0]);
});
app.get('/api/admin/questions', auth, adminOnly, async (_req, res) => {
  const { rows } = await pool.query('SELECT id,prompt,category,options,answer_index,active,created_at FROM questions ORDER BY created_at DESC LIMIT 500'); res.json({ questions: rows });
});
app.post('/api/admin/questions', auth, adminOnly, async (req, res) => {
  try {
    const prompt = String(req.body.prompt || '').trim(), category = String(req.body.category || '').trim(), options = req.body.options, answer = Number(req.body.answerIndex);
    if (prompt.length < 12 || prompt.length > 500 || category.length < 2 || category.length > 60 || !Array.isArray(options) || options.length !== 4 || options.some(x => typeof x !== 'string' || !x.trim()) || !Number.isInteger(answer) || answer < 0 || answer > 3) throw new Error('Provide one clear question, category, four answer choices and the correct choice.');
    const { rows } = await pool.query('INSERT INTO questions(prompt,category,options,answer_index) VALUES($1,$2,$3,$4) RETURNING id,prompt,category,options,answer_index,active', [prompt, category, JSON.stringify(options.map(x => x.trim())), answer]); res.status(201).json(rows[0]);
  } catch (error) { res.status(error.code === '23505' ? 409 : 400).json({ error: error.code === '23505' ? 'This exact question already exists.' : error.message }); }
});
app.patch('/api/admin/questions/:id', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query('UPDATE questions SET active=$1 WHERE id=$2 RETURNING id,active', [req.body.active === true, req.params.id]); if (!rows[0]) return res.sendStatus(404); res.json(rows[0]);
});
function publicUser(user) { return { id: user.id, phone: user.phone, displayName: user.display_name, nickname: user.nickname || '', walletPhone: user.wallet_phone || user.phone, walletBalance: user.wallet_balance, role: user.role || 'member' }; }
function publicUserWithDate(user) { return { ...publicUser(user), createdAt: user.created_at }; }
async function mobileMoney(route, body) {
  const base = process.env.MOBILE_MONEY_BASE_URL || 'https://api.hashback.co.ke';
  if (!process.env.MOBILE_MONEY_API_KEY || !process.env.MOBILE_MONEY_ACCOUNT_ID) throw new Error('Mobile-money service is not configured yet.');
  const response = await fetch(`${base.replace(/\/$/, '')}${route}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.message || 'The mobile-money service is unavailable. Please try again.');
  return result;
}
function validSignature(rawBody, received, secret) {
  const expected = `sha256=${crypto.createHmac('sha256', secret).update(rawBody).digest('hex')}`;
  return Buffer.byteLength(expected) === Buffer.byteLength(received) && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}
async function confirmDeposit(id, providerTransactionId = null) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const updated = await client.query("UPDATE wallet_transactions SET status='confirmed',confirmed_at=NOW(),provider_transaction_id=COALESCE($2,provider_transaction_id) WHERE id=$1 AND status='pending' RETURNING amount,user_id", [id, providerTransactionId]);
    if (updated.rows[0]) await client.query('UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2', [updated.rows[0].amount, updated.rows[0].user_id]);
    await client.query('COMMIT'); return Boolean(updated.rows[0]);
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}
async function boot() { await pool.query(require('fs').readFileSync(path.join(__dirname, 'schema.sql'), 'utf8')); if (process.env.ADMIN_PHONE) await pool.query("UPDATE users SET role='admin' WHERE phone=$1", [cleanPhone(process.env.ADMIN_PHONE)]); await seed(); app.listen(port, () => console.log(`JUA listening on ${port}`)); }
boot().catch(error => { console.error(error); process.exit(1); });
