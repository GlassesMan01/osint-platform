const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const { analyzeTarget } = require('./api/osint');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/analyze', async (req, res) => {
  const { target } = req.body;
  if (!target) {
    return res.status(400).json({ error: 'Target domain/IP is required' });
  }

  try {
    const results = await analyzeTarget(target);
    res.json({ target, timestamp: new Date().toISOString(), results });
  } catch (err) {
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: 'Analysis failed', details: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`OSINT Platform running on http://localhost:${PORT}`);
});
