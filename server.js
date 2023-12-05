import fs from 'fs';
import path from 'path';
import util from 'util';
import express from 'express';
import { config } from 'dotenv';
import fetch from 'node-fetch';
import validator from 'validator';
import bodyParser from 'body-parser';
import { spawn, exec } from 'child_process';
const secretsPath = path.resolve('/etc/secrets', '.env');
const localPath = path.resolve('./.env');
const pathToEnv = fs.existsSync(secretsPath) ? secretsPath : localPath;
config({ path: pathToEnv });
const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;
const executeScript = util.promisify(exec);
app.use(express.static(path.join(process.cwd(), 'public')));

// MongoDB
import { MongoClient, ServerApiVersion } from 'mongodb';
const uri = "mongodb+srv://giri:Admin%2123@giri-mongodb.dtwc2bc.mongodb.net/?retryWrites=true&w=majority";
const client = new MongoClient(uri, {
   tls: true,
   serverApi: ServerApiVersion.v1,
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

app.delete('/items/:vulnerabilityId', async (req, res) => {
   try {
      const vulnerabilityId = req.params.vulnerabilityId;
      await client.connect();
      const collection = client.db("vulnerabilities").collection("mitre");
      const result = await collection.deleteOne({
         VulnerabilityID: vulnerabilityId
      });

      if (result.deletedCount === 0) {
         res.status(404).send('No item with that ID');
      } else {
         console.log(`Deleted item with ID: ${vulnerabilityId}`);
         res.status(200).send('Item deleted');
      }
   } catch (error) {
      res.status(500).send(error.message);
   } finally {
      await client.close();
   }
});

app.put('/items/:vulnerabilityId', async (req, res) => {
   const vulnerabilityId = req.params.vulnerabilityId;
   const updatedData = req.body;
   delete updatedData._id;
   try {
      const vulnerabilityId = req.params.vulnerabilityId;
      const updatedData = req.body;
      await client.connect();
      const collection = client.db("vulnerabilities").collection("mitre");

      const result = await collection.updateOne({
         VulnerabilityID: vulnerabilityId
      }, {
         $set: updatedData
      });

      if (result.matchedCount === 0) {
         res.status(404).send('No item with that ID');
      } else {
         console.log(`Updated item with ID: ${vulnerabilityId}, Data: ${JSON.stringify(updatedData)}`);
         res.status(200).send('Item updated');
      }
   } catch (error) {
      res.status(500).send(error.message);
   } finally {
      await client.close();
   }
});

app.get('/check-repo', async (req, res) => {
   const repositoryUrl = req.query.url;
   const apiUrl = `https://api.github.com/repos/${repositoryUrl}`;
   try {
      const response = await fetch(apiUrl, {
         headers: {
            'Authorization': `token ${process.env.GitHubToken}`
         }
      });
      if (response.ok) {
         res.json({
            exists: true
         });
      } else {
         res.json({
            exists: false
         });
      }
   } catch (error) {
      res.status(500).json({
         error: 'Internal Server Error'
      });
   }
 });

function handleRoute(req, res, fileName) {
   res.sendFile(path.join(process.cwd(), 'public', fileName));
}

app.post('/scan-repo', async (req, res) => {
   const {
      repoUrl
   } = req.body;
   try {
      const {
         stdout,
         stderr
      } = await executeScript(`python3 trivy_detection.py --repo ${repoUrl}`);
      res.status(200).end();
   } catch (error) {
      console.error(`Error executing the script: ${error}`);
      res.status(500).end();
   }
});

app.post('/scan-image', async (req, res) => {
   const {
      imageUrl
   } = req.body;
   const sanitizedImageUrl = validator.escape(imageUrl);
   try {
      const {
         stdout,
         stderr
      } = await executeScript(`python3 trivy_detection.py --image ${sanitizedImageUrl}`);
      res.status(200).end();
   } catch (error) {
      console.error(`Error executing the script: ${error}`);
      res.status(500).end();
   }
});

app.get('/:page', (req, res) => {
   const {
      page
   } = req.params;
   if (page === 'scan-repo' || page.endsWith('.json')) {} else {
      handleRoute(req, res, `${page}.html`);
   }
});

app.listen(PORT, () => {
   console.log(`Server is running on http://localhost:${PORT}`);
});