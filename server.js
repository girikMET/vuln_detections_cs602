import { spawn, exec } from 'child_process';
import path from 'path';
import express from 'express';
import { config } from 'dotenv';
import util from 'util'; 
import validator from 'validator';
config();
const app = express();
const PORT = process.env.PORT || 3000;
const executeScript = util.promisify(exec);
app.use(express.static(path.join(process.cwd(), 'public')));

// MongoDB
import { MongoClient, ServerApiVersion } from 'mongodb';
const uri = "mongodb+srv://giri:Admin%2123@giri-mongodb.dtwc2bc.mongodb.net/?retryWrites=true&w=majority";
const client = new MongoClient(uri, {
  serverApi: ServerApiVersion.v1,
  useNewUrlParser: true,
  useUnifiedTopology: true,
  tls: true, // Enable TLS/SSL connection
  tlsAllowInvalidCertificates: true
});
app.use(express.json());

app.get('/items', async (req, res) => {
  try {
    await client.connect();
    const collection = client.db("vulnerabilities").collection("mitre");
    const items = await collection.find({}).toArray();
    res.json(items);
  } finally {
    await client.close();
  }
});

app.get('/config', (req, res) => {
  res.json({
    GitHubToken: process.env.GitHubToken
  });
});

function handleRoute(req, res, fileName) {
  res.sendFile(path.join(process.cwd(), 'public', fileName));
}

app.post('/scan-repo', async (req, res) => {
  const { repoUrl } = req.body;
  try {
    const { stdout, stderr } = await executeScript(`python3 trivy_detection.py --repo ${repoUrl}`);
    res.status(200).end();
  } catch (error) {
    console.error(`Error executing the script: ${error}`);
    res.status(500).end();
  }
});

app.post('/scan-image', async (req, res) => {
  const { imageUrl } = req.body;
  const sanitizedImageUrl = validator.escape(imageUrl);
  try {
    const { stdout, stderr } = await executeScript(`python3 trivy_detection.py --image ${sanitizedImageUrl}`);
    res.status(200).end();
  } catch (error) {
    console.error(`Error executing the script: ${error}`);
    res.status(500).end();
  }
});

app.get('/:page', (req, res) => {
  const { page } = req.params;
  if (page === 'scan-repo' || page.endsWith('.json')) {
  } else {
    handleRoute(req, res, `${page}.html`);
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});