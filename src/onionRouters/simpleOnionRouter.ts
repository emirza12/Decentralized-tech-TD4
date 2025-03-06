import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, importSymKey, symDecrypt, rsaDecrypt } from "../crypto";
import { webcrypto } from "crypto";
import http from "http";

export type MessageBody = {
  message: string;
};

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // Variables to store information from the last received message
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // Generate RSA keys
  const { publicKey, privateKey } = await generateRsaKeyPair();
  const exportedPubKey = await exportPubKey(publicKey);
  const exportedPrivKey = await exportPrvKey(privateKey);

  // Register the node with the registry
  try {
    const registerNodeBody = {
      nodeId: nodeId,
      pubKey: exportedPubKey
    };

    await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: 'localhost',
        port: REGISTRY_PORT,
        path: '/registerNode',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve(data));
        res.on('error', reject);
      });

      req.on('error', reject);
      req.write(JSON.stringify(registerNodeBody));
      req.end();
    });

    console.log(`Node ${nodeId} registered successfully`);
  } catch (error) {
    console.error(`Failed to register node ${nodeId}:`, error);
  }

  // Function to decrypt a message and extract the destination
  async function decryptMessageLayer(encryptedMessage: string): Promise<{ destination: number; message: string }> {
    try {
      console.log(`Node ${nodeId} decrypting message layer...`);
      
      // Edge case 1: Empty or too short message
      if (!encryptedMessage || encryptedMessage.length < 344) {
        console.error(`Node ${nodeId} received invalid encrypted message: ${encryptedMessage}`);
        return { destination: BASE_ONION_ROUTER_PORT + 1, message: "" };
      }
      
      // The first 344 characters are the symmetric key encrypted with RSA
      const encryptedSymKey = encryptedMessage.slice(0, 344);
      const encryptedData = encryptedMessage.slice(344);
      
      console.log(`Node ${nodeId} encrypted sym key length: ${encryptedSymKey.length}`);
      console.log(`Node ${nodeId} encrypted data length: ${encryptedData.length}`);
      
      // Decrypt the symmetric key with the RSA private key
      let symKeyStr;
      try {
        symKeyStr = await rsaDecrypt(encryptedSymKey, privateKey);
        console.log(`Node ${nodeId} decrypted sym key successfully`);
      } catch (error) {
        console.error(`Node ${nodeId} failed to decrypt symmetric key:`, error);
        return { destination: BASE_ONION_ROUTER_PORT + 1, message: "" };
      }
      
      // Decrypt the message with the symmetric key
      let decryptedData;
      try {
        decryptedData = await symDecrypt(symKeyStr, encryptedData);
        console.log(`Node ${nodeId} decrypted data successfully: ${decryptedData.substring(0, 20)}...`);
      } catch (error) {
        console.error(`Node ${nodeId} failed to decrypt data:`, error);
        return { destination: BASE_ONION_ROUTER_PORT + 1, message: "" };
      }
      
      // Edge case 2: Invalid decrypted data
      if (!decryptedData || decryptedData.length < 10) {
        console.error(`Node ${nodeId} decrypted invalid data: ${decryptedData}`);
        return { destination: BASE_ONION_ROUTER_PORT + 1, message: "" };
      }
      
      // Extract the destination (first 10 characters) and the message
      const destinationStr = decryptedData.slice(0, 10);
      
      // Edge case 3: Invalid destination
      let destination;
      try {
        destination = parseInt(destinationStr);
        if (isNaN(destination)) {
          console.error(`Node ${nodeId} extracted invalid destination: ${destinationStr}`);
          destination = BASE_ONION_ROUTER_PORT + 1;
        }
      } catch (error) {
        console.error(`Node ${nodeId} failed to parse destination:`, error);
        destination = BASE_ONION_ROUTER_PORT + 1;
      }
      
      const message = decryptedData.slice(10);
      
      console.log(`Node ${nodeId} extracted destination: ${destination}`);
      console.log(`Node ${nodeId} extracted message length: ${message.length}`);
      
      return { destination, message };
    } catch (error) {
      console.error(`Error decrypting message in node ${nodeId}:`, error);
      // In case of error, return a default destination and an empty message
      return { destination: BASE_ONION_ROUTER_PORT + 1, message: "" };
    }
  }

  // Routes GET
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.json({ result: exportedPrivKey });
  });

  // Route to receive and forward a message
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message }: MessageBody = req.body;
      
      // Ensure the message is a string, even if it's empty
      const safeMessage = message === null || message === undefined ? "" : message;
      
      console.log(`Node ${nodeId} received encrypted message of length: ${safeMessage.length}`);
      
      // Store the received encrypted message
      lastReceivedEncryptedMessage = safeMessage;
      
      // Decrypt the layer and get the destination and message
      const { destination, message: decryptedMessage } = await decryptMessageLayer(safeMessage);
      
      // Store the decrypted message and destination
      lastReceivedDecryptedMessage = decryptedMessage;
      lastMessageDestination = destination;
      
      console.log(`Node ${nodeId} will forward message to destination: ${destination}`);
      
      // Forward the message to the destination
      await new Promise<void>((resolve, reject) => {
        const req2 = http.request({
          hostname: 'localhost',
          port: destination,
          path: '/message',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          }
        }, (res2) => {
          let data = '';
          res2.on('data', (chunk) => data += chunk);
          res2.on('end', () => {
            console.log(`Node ${nodeId} successfully forwarded message to ${destination}`);
            resolve();
          });
          res2.on('error', (err) => {
            console.error(`Error in response from ${destination}:`, err);
            reject(err);
          });
        });
        
        req2.on('error', (err) => {
          console.error(`Error forwarding message from node ${nodeId} to ${destination}:`, err);
          reject(err);
        });
        
        const bodyToSend = JSON.stringify({ message: decryptedMessage });
        console.log(`Node ${nodeId} sending body of length: ${bodyToSend.length}`);
        req2.write(bodyToSend);
        req2.end();
      });
      
      res.status(200).send("success");
    } catch (err) {
      const error = err as Error;
      console.error(`Error processing message in node ${nodeId}:`, error);
      res.status(500).send(error.message || 'Internal server error');
    }
  });

  return new Promise((resolve, reject) => {
    const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
      console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
      resolve(server);
    }).on('error', (err) => {
      if ((err as any).code === 'EADDRINUSE') {
        console.log(`Port ${BASE_ONION_ROUTER_PORT + nodeId} is busy, retrying...`);
        setTimeout(() => {
          server.close();
          server.listen(BASE_ONION_ROUTER_PORT + nodeId);
        }, 1000);
      } else {
        reject(err);
      }
    });

    process.on('SIGTERM', () => {
      server.close(() => {
        console.log(`Router ${nodeId} server closed`);
      });
    });
  });
}