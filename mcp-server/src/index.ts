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
// Only include tools that have working broker API endpoints
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
