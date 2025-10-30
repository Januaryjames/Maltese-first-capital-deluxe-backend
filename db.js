// db.js
const mongoose = require('mongoose');
const { MongoClient, GridFSBucket } = require('mongodb');

let gfsBucket = null;
let nativeClient = null;

async function connectMongo(uri) {
  // Mongoose connection (ORM)
  await mongoose.connect(uri, { maxPoolSize: 20 });
  // Native client (for GridFS)
  nativeClient = new MongoClient(uri);
  await nativeClient.connect();
  const dbName = mongoose.connection.client.s.options.dbName || mongoose.connection.name;
  const db = nativeClient.db(dbName);
  gfsBucket = new GridFSBucket(db, { bucketName: 'uploads' });
  return { mongoose, gfsBucket };
}

function getGridFSBucket() {
  if (!gfsBucket) throw new Error('GridFS bucket not initialized yet');
  return gfsBucket;
}

async function shutdown() {
  await mongoose.disconnect().catch(()=>{});
  if (nativeClient) await nativeClient.close().catch(()=>{});
}

module.exports = { connectMongo, getGridFSBucket, shutdown };
