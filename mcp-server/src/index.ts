#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from "axios";
import { z } from "zod";

// Environment configuration
const BROKER_URL = process.env.BROKER_URL || "http://broker.kguardian.svc.cluster.local:9090";

// Create axios client for broker API
const brokerClient: AxiosInstance = axios.create({
  baseURL: BROKER_URL,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Define MCP tools for kguardian
const tools: Tool[] = [
  {
    name: "get_pod_network_traffic",
    description: "Get network traffic data for a specific pod by namespace and pod name. Returns source/destination IPs, ports, protocols, and connection counts.",
    inputSchema: {
      type: "object",
      properties: {
        namespace: {
          type: "string",
          description: "The Kubernetes namespace of the pod",
        },
        pod_name: {
          type: "string",
          description: "The name of the pod",
        },
      },
      required: ["namespace", "pod_name"],
    },
  },
  {
    name: "get_pod_syscalls",
    description: "Get system call (syscall) data for a specific pod. Returns the syscalls made by the pod with their frequencies. Useful for security analysis and seccomp profile generation.",
    inputSchema: {
      type: "object",
      properties: {
        namespace: {
          type: "string",
          description: "The Kubernetes namespace of the pod",
        },
        pod_name: {
          type: "string",
          description: "The name of the pod",
        },
      },
      required: ["namespace", "pod_name"],
    },
  },
  {
    name: "get_pod_packet_drops",
    description: "Get packet drop events for a specific pod. Returns information about dropped network packets including reasons and statistics. Useful for debugging network issues.",
    inputSchema: {
      type: "object",
      properties: {
        namespace: {
          type: "string",
          description: "The Kubernetes namespace of the pod",
        },
        pod_name: {
          type: "string",
          description: "The name of the pod",
        },
      },
      required: ["namespace", "pod_name"],
    },
  },
  {
    name: "list_all_pods",
    description: "List all monitored pods across all namespaces. Returns basic pod information including names, namespaces, and IPs. Use this to discover what pods are being monitored.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "search_pods_by_namespace",
    description: "Search for pods within a specific namespace. Returns all pods in that namespace with their details.",
    inputSchema: {
      type: "object",
      properties: {
        namespace: {
          type: "string",
          description: "The Kubernetes namespace to search in",
        },
      },
      required: ["namespace"],
    },
  },
  {
    name: "analyze_security_events",
    description: "Analyze security-related events across the cluster. Aggregates syscall data and network traffic to identify potential security issues or anomalies.",
    inputSchema: {
      type: "object",
      properties: {
        namespace: {
          type: "string",
          description: "Optional: Filter by specific namespace",
        },
      },
    },
  },
];

// Zod schemas for validation
const NetworkTrafficArgs = z.object({
  namespace: z.string(),
  pod_name: z.string(),
});

const SyscallArgs = z.object({
  namespace: z.string(),
  pod_name: z.string(),
});

const PacketDropArgs = z.object({
  namespace: z.string(),
  pod_name: z.string(),
});

const NamespaceSearchArgs = z.object({
  namespace: z.string(),
});

const SecurityAnalysisArgs = z.object({
  namespace: z.string().optional(),
});

// Tool implementation functions
async function getPodNetworkTraffic(namespace: string, podName: string): Promise<string> {
  try {
    const response = await brokerClient.get(`/pod/traffic/name/${namespace}/${podName}`);
    return JSON.stringify(response.data, null, 2);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return `Error fetching network traffic: ${error.response?.status} - ${error.message}`;
    }
    return `Error fetching network traffic: ${error}`;
  }
}

async function getPodSyscalls(namespace: string, podName: string): Promise<string> {
  try {
    const response = await brokerClient.get(`/pod/syscalls/name/${namespace}/${podName}`);
    return JSON.stringify(response.data, null, 2);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return `Error fetching syscalls: ${error.response?.status} - ${error.message}`;
    }
    return `Error fetching syscalls: ${error}`;
  }
}

async function getPodPacketDrops(namespace: string, podName: string): Promise<string> {
  try {
    const response = await brokerClient.get(`/pod/packet_drop/name/${namespace}/${podName}`);
    return JSON.stringify(response.data, null, 2);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return `Error fetching packet drops: ${error.response?.status} - ${error.message}`;
    }
    return `Error fetching packet drops: ${error}`;
  }
}

async function listAllPods(): Promise<string> {
  try {
    // This is a synthetic operation - we'd need to add this endpoint to broker
    // For now, return a helpful message
    return JSON.stringify({
      message: "Pod listing endpoint not yet implemented in broker API",
      suggestion: "Use search_pods_by_namespace with a known namespace instead",
    }, null, 2);
  } catch (error) {
    return `Error listing pods: ${error}`;
  }
}

async function searchPodsByNamespace(namespace: string): Promise<string> {
  try {
    // This would require a new broker endpoint to list pods by namespace
    return JSON.stringify({
      message: `Namespace search endpoint not yet implemented for: ${namespace}`,
      suggestion: "Query specific pods using get_pod_network_traffic or get_pod_syscalls",
    }, null, 2);
  } catch (error) {
    return `Error searching pods: ${error}`;
  }
}

async function analyzeSecurityEvents(namespace?: string): Promise<string> {
  try {
    // This is an aggregation operation - could be implemented as a new broker endpoint
    const analysis = {
      message: "Security analysis aggregation not yet implemented",
      namespace: namespace || "all",
      suggestion: "Query individual pods first using get_pod_syscalls and get_pod_network_traffic",
    };
    return JSON.stringify(analysis, null, 2);
  } catch (error) {
    return `Error analyzing security events: ${error}`;
  }
}

// Create and configure MCP server
const server = new Server(
  {
    name: "kguardian-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register tool list handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Register tool call handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "get_pod_network_traffic": {
        const validated = NetworkTrafficArgs.parse(args);
        const result = await getPodNetworkTraffic(validated.namespace, validated.pod_name);
        return {
          content: [
            {
              type: "text",
              text: result,
            },
          ],
        };
      }

      case "get_pod_syscalls": {
        const validated = SyscallArgs.parse(args);
        const result = await getPodSyscalls(validated.namespace, validated.pod_name);
        return {
          content: [
            {
              type: "text",
              text: result,
            },
          ],
        };
      }

      case "get_pod_packet_drops": {
        const validated = PacketDropArgs.parse(args);
        const result = await getPodPacketDrops(validated.namespace, validated.pod_name);
        return {
          content: [
            {
              type: "text",
              text: result,
            },
          ],
        };
      }

      case "list_all_pods": {
        const result = await listAllPods();
        return {
          content: [
            {
              type: "text",
              text: result,
            },
          ],
        };
      }

      case "search_pods_by_namespace": {
        const validated = NamespaceSearchArgs.parse(args);
        const result = await searchPodsByNamespace(validated.namespace);
        return {
          content: [
            {
              type: "text",
              text: result,
            },
          ],
        };
      }

      case "analyze_security_events": {
        const validated = SecurityAnalysisArgs.parse(args);
        const result = await analyzeSecurityEvents(validated.namespace);
        return {
          content: [
            {
              type: "text",
              text: result,
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Invalid arguments: ${error.message}`);
    }
    throw error;
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("kguardian MCP server running on stdio");
  console.error(`Broker URL: ${BROKER_URL}`);
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
