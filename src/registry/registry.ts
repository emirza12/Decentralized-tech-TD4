import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Storage for registered nodes
  const registeredNodes: Node[] = [];

  // Implementation of the /status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to register a node
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;
    
    // Check if the node already exists
    const existingNodeIndex = registeredNodes.findIndex(node => node.nodeId === nodeId);
    
    if (existingNodeIndex !== -1) {
      // Update the existing node
      registeredNodes[existingNodeIndex] = { nodeId, pubKey };
    } else {
      // Add a new node
      registeredNodes.push({ nodeId, pubKey });
    }
    
    res.status(200).send();
  });

  // Route to retrieve the list of nodes
  _registry.get("/getNodeRegistry", (req, res) => {
    const response: GetNodeRegistryBody = {
      nodes: registeredNodes
    };
    res.json(response);
  });

  // Modify server creation to handle port already in use
  return new Promise((resolve, reject) => {
    const server = _registry.listen(REGISTRY_PORT, () => {
      console.log(`Registry is listening on port ${REGISTRY_PORT}`);
      resolve(server);
    }).on('error', (err) => {
      if ((err as any).code === 'EADDRINUSE') {
        console.log(`Port ${REGISTRY_PORT} is busy, retrying...`);
        setTimeout(() => {
          server.close();
          server.listen(REGISTRY_PORT);
        }, 1000);
      } else {
        reject(err);
      }
    });

    process.on('SIGTERM', () => {
      server.close(() => {
        console.log('Registry server closed');
      });
    });
  });
}
