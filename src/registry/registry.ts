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

  // Store registered nodes
  const registeredNodes: Node[] = [];

  // Status route that returns "live"
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to register a new node
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;
    
    const existingNode = registeredNodes.find(node => node.nodeId === nodeId);
    if (existingNode) {
      return res.status(400).json({ error: "Node already registered" });
    }

    registeredNodes.push({ nodeId, pubKey });
    return res.status(200).json({ message: "Node registered successfully" });
  });

  // Route to get all registered nodes
  _registry.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes: registeredNodes });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
