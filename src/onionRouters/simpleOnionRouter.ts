import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";
import { generateRsaKeyPair, exportPrvKey, exportPubKey } from "../crypto";
import { REGISTRY_PORT } from "../config";

export async function simpleOnionRouter(nodeId: number) {
  // 1. Create keys before starting the server
  const { publicKey, privateKey } = await generateRsaKeyPair();
  const exportedPublicKey = await exportPubKey(publicKey);

  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // TODO implement the status route
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    const exportedPrivateKey = await exportPrvKey(privateKey);
    res.json({ result: exportedPrivateKey });
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

  onionRouter.post("/message", (req, res) => {
    lastReceivedEncryptedMessage = req.body.message;
    lastReceivedDecryptedMessage = req.body.decryptedMessage;
    lastMessageDestination = req.body.destinationPort;
    res.sendStatus(200);
  });

  // 2. Start server and register node
  return new Promise((resolve, reject) => {
    const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, async () => {
      console.log(
        `Onion router ${nodeId} is listening on port ${
          BASE_ONION_ROUTER_PORT + nodeId
        }`
      );

      try {
        const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            nodeId,
            pubKey: exportedPublicKey
          })
        });

        if (!response.ok) {
          server.close();
          reject(new Error(`Failed to register node ${nodeId}`));
          return;
        }
        resolve(server);
      } catch (error) {
        server.close();
        reject(error);
      }
    });

    server.on('error', (error) => {
      reject(error);
    });
  });
}
