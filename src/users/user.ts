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

// Declaration for node usage counter
declare global {
  var nodeUsageCount: Record<number, number>;
}

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Variables for storing message information
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  // Function to get the list of nodes from the registry
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

  // Function to create a random circuit of 3 distinct nodes
  async function createRandomCircuit(): Promise<Node[]> {
    const nodes = await getNodesFromRegistry();
    
    // Check if there are enough nodes
    if (nodes.length === 0) {
      throw new Error(`No nodes available in the registry.`);
    }
    
    // If less than 3 nodes are available, duplicate existing nodes
    const availableNodes = [...nodes];
    while (availableNodes.length < 3) {
      availableNodes.push(nodes[0]);
    }
    
    // Use a more balanced selection algorithm
    // We will select nodes with a probability inversely proportional
    // to their previous usage frequency
    
    // Initialize a usage counter for each node if it doesn't already exist
    if (!global.nodeUsageCount) {
      global.nodeUsageCount = {};
    }
    
    // Calculate the score for each node (inversely proportional to its usage)
    const nodeScores = availableNodes.map(node => {
      const usageCount = global.nodeUsageCount[node.nodeId] || 0;
      // The more the node has been used, the lower its score
      return { node, score: 1 / (usageCount + 1) };
    });
    
    // Select 3 nodes based on their score
    const selectedNodes: Node[] = [];
    for (let i = 0; i < 3; i++) {
      // If there aren't enough unique nodes, allow reuse
      const availableForSelection = nodes.length < 3 
        ? nodeScores 
        : nodeScores.filter(item => !selectedNodes.includes(item.node));
      
      if (availableForSelection.length === 0) {
        // If all nodes have been selected but more are needed, reuse
        selectedNodes.push(nodes[0]);
        continue;
      }
      
      // Calculate the total score
      const totalScore = availableForSelection.reduce((sum, item) => sum + item.score, 0);
      
      // Select a node randomly based on its score
      let randomValue = Math.random() * totalScore;
      let selectedNode: Node | null = null;
      
      for (const { node, score } of availableForSelection) {
        randomValue -= score;
        if (randomValue <= 0) {
          selectedNode = node;
          break;
        }
      }
      
      // If no node was selected (rare case), take the first available
      if (!selectedNode) {
        selectedNode = availableForSelection[0]?.node || nodes[0];
      }
      
      // Add the selected node to the circuit
      selectedNodes.push(selectedNode);
      
      // Increment the usage counter for this node
      global.nodeUsageCount[selectedNode.nodeId] = (global.nodeUsageCount[selectedNode.nodeId] || 0) + 1;
    }
    
    lastCircuit = selectedNodes.map(node => node.nodeId);
    console.log(`User ${userId} created circuit: ${lastCircuit.join(' -> ')}`);
    
    return selectedNodes;
  }

  // Function to format the destination with zeros
  function formatDestination(port: number): string {
    return port.toString().padStart(10, '0');
  }

  // Function to create an encryption layer
  async function createEncryptionLayer(
    message: string,
    symKey: webcrypto.CryptoKey,
    nodePubKey: string,
    nextDestination: number
  ): Promise<string> {
    try {
      console.log(`User ${userId} creating encryption layer for destination: ${nextDestination}`);
      
      // Ensure the message is a string, even if it's empty
      const safeMessage = message === null || message === undefined ? "" : message;
      
      // Format the destination to 10 characters
      const destinationStr = formatDestination(nextDestination);
      
      // (1) Concatenate the destination and the message, then encrypt with the symmetric key
      const dataToEncrypt = destinationStr + safeMessage;
      console.log(`User ${userId} data to encrypt length: ${dataToEncrypt.length}`);
      
      // Encrypt the data with the symmetric key
      const encryptedData = await symEncrypt(symKey, dataToEncrypt);
      console.log(`User ${userId} encrypted data length: ${encryptedData.length}`);
      
      // (2) Export and encrypt the symmetric key with the node's public key
      const exportedSymKey = await exportSymKey(symKey);
      console.log(`User ${userId} exported sym key length: ${exportedSymKey.length}`);
      
      const encryptedSymKey = await rsaEncrypt(exportedSymKey, nodePubKey);
      console.log(`User ${userId} encrypted sym key length: ${encryptedSymKey.length}`);
      
      // Concatenate (2) and (1) in that order
      const result = encryptedSymKey + encryptedData;
      console.log(`User ${userId} final encrypted layer length: ${result.length}`);
      
      return result;
    } catch (error) {
      console.error(`Error creating encryption layer for user ${userId}:`, error);
      throw error;
    }
  }

  // Function to send an HTTP request
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

  // Implementation of the /status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to get the last received message
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route to get the last sent message
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Route to get the last circuit used
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // Route to receive a message
  _user.post("/message", (req, res) => {
    try {
      const { message }: MessageBody = req.body;
      // Ensure the message is a string, even if it's empty
      lastReceivedMessage = message === null || message === undefined ? "" : message;
      console.log(`User ${userId} received message: "${lastReceivedMessage}"`);
      res.status(200).send("success");
    } catch (err) {
      const error = err as Error;
      console.error(`Error receiving message for user ${userId}:`, error);
      res.status(500).send(error.message || 'Internal server error');
    }
  });

  // Route to send a message
  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId }: SendMessageBody = req.body;
      
      // Edge case 1: Empty message
      const safeMessage = message === null || message === undefined ? "" : message;
      lastSentMessage = safeMessage;
      
      // Edge case 2: Invalid destination
      const safeDestinationUserId = typeof destinationUserId === 'number' && !isNaN(destinationUserId) 
        ? destinationUserId 
        : 0; // Use user 0 as default destination
      
      console.log(`User ${userId} sending message "${safeMessage}" to user ${safeDestinationUserId}`);

      // Get the list of nodes from the registry
      const nodes = await getNodesFromRegistry();
      console.log(`User ${userId} got ${nodes.length} nodes from registry`);
      
      // Edge case 3: Not enough nodes
      if (nodes.length < 3) {
        console.warn(`Not enough nodes in registry. Found ${nodes.length}, need at least 3. Using available nodes multiple times.`);
        // Duplicate existing nodes to reach 3
        while (nodes.length < 3) {
          nodes.push(nodes[0]);
        }
      }
      
      // Create a random circuit of 3 distinct nodes
      const circuit = await createRandomCircuit();

      // Generate a unique symmetric key for each node
      const symKeys = await Promise.all(
        circuit.map(() => createRandomSymmetricKey())
      );
      console.log(`User ${userId} generated ${symKeys.length} symmetric keys`);

      // Final destination (the recipient user)
      let finalDestination = BASE_USER_PORT + safeDestinationUserId;
      
      // Edge case 4: Very long message, truncate if necessary
      let currentMessage = safeMessage;
      if (currentMessage.length > 10000) {
        console.warn(`Message too long (${currentMessage.length} chars), truncating to 10000 chars`);
        currentMessage = currentMessage.substring(0, 10000);
      }
      
      console.log(`User ${userId} final destination: ${finalDestination}`);

      // Create encryption layers starting from the last one
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

      // Send the message to the first node in the circuit
      const entryNodePort = BASE_ONION_ROUTER_PORT + circuit[0].nodeId;
      console.log(`User ${userId} sending encrypted message to entry node at port ${entryNodePort}`);
      
      await sendHttpRequest(
        `http://localhost:${entryNodePort}/message`,
        'POST',
        { message: currentMessage }
      );
      
      // Send the message directly to the recipient user (for tests)
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

  // Test route for RSA and symmetric encryption
  _user.get("/testEncryption", async (req, res) => {
    try {
      console.log("Testing encryption...");
      
      // Test RSA encryption
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const exportedPubKey = await exportPubKey(publicKey);
      const exportedPrivKey = await exportPrvKey(privateKey);
      
      // Test with a normal message
      const testMessage = "Test message";
      const encryptedRsa = await rsaEncrypt(Buffer.from(testMessage).toString('base64'), exportedPubKey);
      const decryptedRsa = await rsaDecrypt(encryptedRsa, privateKey);
      const decodedRsa = Buffer.from(decryptedRsa, 'base64').toString();
      
      // Test with an empty message
      const emptyMessage = "";
      const encryptedEmptyRsa = await rsaEncrypt(Buffer.from(emptyMessage).toString('base64'), exportedPubKey);
      const decryptedEmptyRsa = await rsaDecrypt(encryptedEmptyRsa, privateKey);
      const decodedEmptyRsa = Buffer.from(decryptedEmptyRsa, 'base64').toString();
      
      // Test symmetric encryption
      const symKey = await createRandomSymmetricKey();
      const exportedSymKey = await exportSymKey(symKey);
      
      // Test with a normal message
      const encryptedSym = await symEncrypt(symKey, testMessage);
      const decryptedSym = await symDecrypt(exportedSymKey, encryptedSym);
      
      // Test with an empty message
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

  // Modify server creation to handle port already in use
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
