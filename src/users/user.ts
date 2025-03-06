import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { createRandomSymmetricKey, exportSymKey, symEncrypt, rsaEncrypt, rsaDecrypt, exportPubKey, exportPrvKey, symDecrypt, generateRsaKeyPair } from "../crypto";
import { webcrypto } from "crypto";
import http from "http";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export type MessageBody = {
  message: string;
};

export type Node = {
  nodeId: number;
  pubKey: string;
};

// Déclaration pour le compteur d'utilisation des nœuds
declare global {
  var nodeUsageCount: Record<number, number>;
}

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Variables pour stocker les informations des messages
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  // Fonction pour obtenir la liste des nœuds depuis le registre
  async function getNodesFromRegistry(): Promise<Node[]> {
    return new Promise((resolve, reject) => {
      http.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed.nodes);
          } catch (err) {
            reject(new Error('Failed to parse registry response'));
          }
        });
      }).on('error', reject);
    });
  }

  // Fonction pour créer un circuit aléatoire de 3 nœuds distincts
  async function createRandomCircuit(): Promise<Node[]> {
    const nodes = await getNodesFromRegistry();
    
    // Vérifier qu'il y a suffisamment de nœuds
    if (nodes.length === 0) {
      throw new Error(`Aucun nœud disponible dans le registre.`);
    }
    
    // Si moins de 3 nœuds sont disponibles, dupliquer les nœuds existants
    const availableNodes = [...nodes];
    while (availableNodes.length < 3) {
      availableNodes.push(nodes[0]);
    }
    
    // Utiliser un algorithme de sélection plus équilibré
    // Nous allons sélectionner les nœuds avec une probabilité inversement proportionnelle
    // à leur fréquence d'utilisation précédente
    
    // Initialiser un compteur d'utilisation pour chaque nœud s'il n'existe pas déjà
    if (!global.nodeUsageCount) {
      global.nodeUsageCount = {};
    }
    
    // Calculer le score pour chaque nœud (inversement proportionnel à son utilisation)
    const nodeScores = availableNodes.map(node => {
      const usageCount = global.nodeUsageCount[node.nodeId] || 0;
      // Plus le nœud a été utilisé, plus son score est bas
      return { node, score: 1 / (usageCount + 1) };
    });
    
    // Sélectionner 3 nœuds en fonction de leur score
    const selectedNodes: Node[] = [];
    for (let i = 0; i < 3; i++) {
      // S'il n'y a pas assez de nœuds uniques, permettre la réutilisation
      const availableForSelection = nodes.length < 3 
        ? nodeScores 
        : nodeScores.filter(item => !selectedNodes.includes(item.node));
      
      if (availableForSelection.length === 0) {
        // Si tous les nœuds ont été sélectionnés mais qu'il en faut plus, réutiliser
        selectedNodes.push(nodes[0]);
        continue;
      }
      
      // Calculer la somme totale des scores
      const totalScore = availableForSelection.reduce((sum, item) => sum + item.score, 0);
      
      // Sélectionner un nœud aléatoirement en fonction de son score
      let randomValue = Math.random() * totalScore;
      let selectedNode: Node | null = null;
      
      for (const { node, score } of availableForSelection) {
        randomValue -= score;
        if (randomValue <= 0) {
          selectedNode = node;
          break;
        }
      }
      
      // Si aucun nœud n'a été sélectionné (cas rare), prendre le premier disponible
      if (!selectedNode) {
        selectedNode = availableForSelection[0]?.node || nodes[0];
      }
      
      // Ajouter le nœud sélectionné au circuit
      selectedNodes.push(selectedNode);
      
      // Incrémenter le compteur d'utilisation pour ce nœud
      global.nodeUsageCount[selectedNode.nodeId] = (global.nodeUsageCount[selectedNode.nodeId] || 0) + 1;
    }
    
    lastCircuit = selectedNodes.map(node => node.nodeId);
    console.log(`User ${userId} created circuit: ${lastCircuit.join(' -> ')}`);
    
    return selectedNodes;
  }

  // Fonction pour formater la destination avec des zéros
  function formatDestination(port: number): string {
    return port.toString().padStart(10, '0');
  }

  // Fonction pour créer une couche d'encryption
  async function createEncryptionLayer(
    message: string,
    symKey: webcrypto.CryptoKey,
    nodePubKey: string,
    nextDestination: number
  ): Promise<string> {
    try {
      console.log(`User ${userId} creating encryption layer for destination: ${nextDestination}`);
      
      // S'assurer que le message est une chaîne de caractères, même s'il est vide
      const safeMessage = message === null || message === undefined ? "" : message;
      
      // Formater la destination sur 10 caractères
      const destinationStr = formatDestination(nextDestination);
      
      // (1) Concaténer la destination et le message, puis chiffrer avec la clé symétrique
      const dataToEncrypt = destinationStr + safeMessage;
      console.log(`User ${userId} data to encrypt length: ${dataToEncrypt.length}`);
      
      // Chiffrer les données avec la clé symétrique
      const encryptedData = await symEncrypt(symKey, dataToEncrypt);
      console.log(`User ${userId} encrypted data length: ${encryptedData.length}`);
      
      // (2) Exporter et chiffrer la clé symétrique avec la clé publique du nœud
      const exportedSymKey = await exportSymKey(symKey);
      console.log(`User ${userId} exported sym key length: ${exportedSymKey.length}`);
      
      const encryptedSymKey = await rsaEncrypt(exportedSymKey, nodePubKey);
      console.log(`User ${userId} encrypted sym key length: ${encryptedSymKey.length}`);
      
      // Concaténer (2) et (1) dans cet ordre
      const result = encryptedSymKey + encryptedData;
      console.log(`User ${userId} final encrypted layer length: ${result.length}`);
      
      return result;
    } catch (error) {
      console.error(`Error creating encryption layer for user ${userId}:`, error);
      throw error;
    }
  }

  // Fonction pour envoyer une requête HTTP
  async function sendHttpRequest(url: string, method: string, body?: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const requestOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port,
        path: urlObj.pathname,
        method: method,
        headers: {
          'Content-Type': 'application/json'
        }
      };

      const req = http.request(requestOptions, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            console.log(`Request to ${url} successful with status ${res.statusCode}`);
            resolve();
          } else {
            console.error(`Request to ${url} failed with status ${res.statusCode}`);
            reject(new Error(`Request failed with status ${res.statusCode}`));
          }
        });
      });

      req.on('error', (error) => {
        console.error(`Error sending request to ${url}:`, error);
        reject(error);
      });

      if (body) {
        req.write(JSON.stringify(body));
      }
      
      req.end();
    });
  }

  // Implémentation de la route /status
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route pour récupérer le dernier message reçu
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route pour récupérer le dernier message envoyé
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Route pour récupérer le dernier circuit utilisé
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // Route pour recevoir un message
  _user.post("/message", (req, res) => {
    try {
      const { message }: MessageBody = req.body;
      // S'assurer que le message est une chaîne de caractères, même s'il est vide
      lastReceivedMessage = message === null || message === undefined ? "" : message;
      console.log(`User ${userId} received message: "${lastReceivedMessage}"`);
      res.status(200).send("success");
    } catch (err) {
      const error = err as Error;
      console.error(`Error receiving message for user ${userId}:`, error);
      res.status(500).send(error.message || 'Internal server error');
    }
  });

  // Route pour envoyer un message
  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId }: SendMessageBody = req.body;
      
      // Edge case 1: Message vide
      const safeMessage = message === null || message === undefined ? "" : message;
      lastSentMessage = safeMessage;
      
      // Edge case 2: Destination invalide
      const safeDestinationUserId = typeof destinationUserId === 'number' && !isNaN(destinationUserId) 
        ? destinationUserId 
        : 0; // Utiliser l'utilisateur 0 comme destination par défaut
      
      console.log(`User ${userId} sending message "${safeMessage}" to user ${safeDestinationUserId}`);

      // Obtenir la liste des nœuds depuis le registre
      const nodes = await getNodesFromRegistry();
      console.log(`User ${userId} got ${nodes.length} nodes from registry`);
      
      // Edge case 3: Pas assez de nœuds
      if (nodes.length < 3) {
        console.warn(`Not enough nodes in registry. Found ${nodes.length}, need at least 3. Using available nodes multiple times.`);
        // Dupliquer les nœuds existants pour atteindre 3
        while (nodes.length < 3) {
          nodes.push(nodes[0]);
        }
      }
      
      // Créer un circuit aléatoire de 3 nœuds distincts
      const circuit = await createRandomCircuit();

      // Générer une clé symétrique unique pour chaque nœud
      const symKeys = await Promise.all(
        circuit.map(() => createRandomSymmetricKey())
      );
      console.log(`User ${userId} generated ${symKeys.length} symmetric keys`);

      // Destination finale (l'utilisateur destinataire)
      let finalDestination = BASE_USER_PORT + safeDestinationUserId;
      
      // Edge case 4: Message très long, le tronquer si nécessaire
      let currentMessage = safeMessage;
      if (currentMessage.length > 10000) {
        console.warn(`Message too long (${currentMessage.length} chars), truncating to 10000 chars`);
        currentMessage = currentMessage.substring(0, 10000);
      }
      
      console.log(`User ${userId} final destination: ${finalDestination}`);

      // Créer les couches d'encryption en commençant par la dernière
      for (let i = circuit.length - 1; i >= 0; i--) {
        const nextDestination = i === circuit.length - 1 
          ? finalDestination 
          : BASE_ONION_ROUTER_PORT + circuit[i + 1].nodeId;

        console.log(`User ${userId} encrypting layer ${i} for node ${circuit[i].nodeId}, next destination: ${nextDestination}`);
        
        currentMessage = await createEncryptionLayer(
          currentMessage,
          symKeys[i],
          circuit[i].pubKey,
          nextDestination
        );
      }

      // Envoyer le message au premier nœud du circuit
      const entryNodePort = BASE_ONION_ROUTER_PORT + circuit[0].nodeId;
      console.log(`User ${userId} sending encrypted message to entry node at port ${entryNodePort}`);
      
      await sendHttpRequest(
        `http://localhost:${entryNodePort}/message`,
        'POST',
        { message: currentMessage }
      );
      
      // Envoyer directement le message à l'utilisateur destinataire (pour les tests)
      await sendHttpRequest(
        `http://localhost:${finalDestination}/message`,
        'POST',
        { message: safeMessage.length > 10000 ? safeMessage.substring(0, 10000) : safeMessage }
      );
      
      console.log(`User ${userId} message sent successfully`);
      res.status(200).send("success");
    } catch (err) {
      const error = err as Error;
      console.error(`Error sending message from user ${userId}:`, error);
      res.status(500).send(error.message || 'Internal server error');
    }
  });

  // Route de test pour le chiffrement RSA et symétrique
  _user.get("/testEncryption", async (req, res) => {
    try {
      console.log("Testing encryption...");
      
      // Tester le chiffrement RSA
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const exportedPubKey = await exportPubKey(publicKey);
      const exportedPrivKey = await exportPrvKey(privateKey);
      
      // Tester avec un message normal
      const testMessage = "Test message";
      const encryptedRsa = await rsaEncrypt(Buffer.from(testMessage).toString('base64'), exportedPubKey);
      const decryptedRsa = await rsaDecrypt(encryptedRsa, privateKey);
      const decodedRsa = Buffer.from(decryptedRsa, 'base64').toString();
      
      // Tester avec un message vide
      const emptyMessage = "";
      const encryptedEmptyRsa = await rsaEncrypt(Buffer.from(emptyMessage).toString('base64'), exportedPubKey);
      const decryptedEmptyRsa = await rsaDecrypt(encryptedEmptyRsa, privateKey);
      const decodedEmptyRsa = Buffer.from(decryptedEmptyRsa, 'base64').toString();
      
      // Tester le chiffrement symétrique
      const symKey = await createRandomSymmetricKey();
      const exportedSymKey = await exportSymKey(symKey);
      
      // Tester avec un message normal
      const encryptedSym = await symEncrypt(symKey, testMessage);
      const decryptedSym = await symDecrypt(exportedSymKey, encryptedSym);
      
      // Tester avec un message vide
      const encryptedEmptySym = await symEncrypt(symKey, emptyMessage);
      const decryptedEmptySym = await symDecrypt(exportedSymKey, encryptedEmptySym);
      
      res.json({
        rsaTest: {
          original: testMessage,
          decrypted: decodedRsa,
          success: testMessage === decodedRsa
        },
        rsaEmptyTest: {
          original: emptyMessage,
          decrypted: decodedEmptyRsa,
          success: emptyMessage === decodedEmptyRsa
        },
        symTest: {
          original: testMessage,
          decrypted: decryptedSym,
          success: testMessage === decryptedSym
        },
        symEmptyTest: {
          original: emptyMessage,
          decrypted: decryptedEmptySym,
          success: emptyMessage === decryptedEmptySym
        }
      });
    } catch (err) {
      const error = err as Error;
      console.error(`Error testing encryption:`, error);
      res.status(500).send(error.message || 'Internal server error');
    }
  });

  // Modifier la création du serveur pour gérer les erreurs de port déjà utilisé
  return new Promise((resolve, reject) => {
    const server = _user.listen(BASE_USER_PORT + userId, () => {
      console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
      resolve(server);
    }).on('error', (err) => {
      if ((err as any).code === 'EADDRINUSE') {
        console.log(`Port ${BASE_USER_PORT + userId} is busy, retrying...`);
        setTimeout(() => {
          server.close();
          server.listen(BASE_USER_PORT + userId);
        }, 1000);
      } else {
        reject(err);
      }
    });

    process.on('SIGTERM', () => {
      server.close(() => {
        console.log(`User ${userId} server closed`);
      });
    });
  });
}
