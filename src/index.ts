import { launchOnionRouters } from "./onionRouters/launchOnionRouters";
import { launchRegistry } from "./registry/registry";
import { launchUsers } from "./users/launchUsers";

export async function launchNetwork(nbNodes: number, nbUsers: number) {
  try {
    // launch node registry
    const registry = await launchRegistry();
    
    // Wait for the registry to be ready
    await new Promise(resolve => setTimeout(resolve, 2000));

    // launch all nodes
    const onionServers = await launchOnionRouters(nbNodes);
    
    // Wait for nodes to register
    await new Promise(resolve => setTimeout(resolve, 3000));

    // launch all users
    const userServers = await launchUsers(nbUsers);
    
    // Wait for users to be ready
    await new Promise(resolve => setTimeout(resolve, 2000));

    return [registry, ...onionServers, ...userServers];
  } catch (error) {
    console.error("Error launching network:", error);
    throw error;
  }
}