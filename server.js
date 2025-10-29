// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(cors({
  origin: [/^https?:\/\/localhost(:\d+)?$/, /maltesefirst\.com$/],
  credentials: false
}));

mongoose.connect(process.env.MONGO_URI, { autoIndex: true });

app.get('/api/health', (_,res)=>res.json({ ok:true, status:'healthy' }));

app.use('/api/clients', require('./routes/clients'));
app.use('/api/auth',    require('./routes/auth'));
app.use('/api/admin',   require('./routes/admin'));

const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=> console.log('MFC backend on', PORT));
