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

  // Stockage des nœuds enregistrés
  const registeredNodes: Node[] = [];

  // Implémentation de la route /status
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Route pour enregistrer un nœud
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;
    
    // Vérifier si le nœud existe déjà
    const existingNodeIndex = registeredNodes.findIndex(node => node.nodeId === nodeId);
    
    if (existingNodeIndex !== -1) {
      // Mettre à jour le nœud existant
      registeredNodes[existingNodeIndex] = { nodeId, pubKey };
    } else {
      // Ajouter un nouveau nœud
      registeredNodes.push({ nodeId, pubKey });
    }
    
    res.status(200).send();
  });

  // Route pour récupérer la liste des nœuds
  _registry.get("/getNodeRegistry", (req, res) => {
    const response: GetNodeRegistryBody = {
      nodes: registeredNodes
    };
    res.json(response);
  });

  // Modifier la création du serveur pour gérer les erreurs de port déjà utilisé
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
