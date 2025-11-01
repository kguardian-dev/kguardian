# Kube Guardian UI - Architecture

## Overview

This is a modern, single-page web application for visualizing Kubernetes pod network traffic and security monitoring data collected by the Kube Guardian system.

## Technology Stack

### Core
- **React 19**: Modern UI framework with concurrent features
- **TypeScript**: Type-safe development
- **Vite 7**: Lightning-fast build tooling and HMR

### Visualization
- **React Flow 11**: Network graph visualization library
  - Provides node-based UI with drag-and-drop
  - Handles edge routing and layout
  - Supports custom node components

### Styling
- **TailwindCSS 4**: Utility-first CSS framework
  - Uses new `@theme` directive for custom colors
  - Configured with Hubble-inspired dark theme
  - PostCSS with autoprefixer

### UI Components
- **Lucide React**: Modern icon library
  - Lightweight and tree-shakeable
  - Consistent icon design

### HTTP Client
- **Axios**: Promise-based HTTP client
  - Connects to Broker API (default: localhost:9090)
  - Centralized API client pattern

## Architecture Patterns

### Component Structure

```
App (Main Container)
├── Header
│   ├── Branding (Shield icon + title)
│   ├── NamespaceSelector
│   └── RefreshButton
├── Main Content
│   ├── ErrorDisplay (conditional)
│   ├── LoadingState (conditional)
│   └── Content (when data loaded)
│       ├── NetworkGraph
│       │   └── PodNode (repeated)
│       └── DataTable (bottom panel)
└── Footer (stats)
```

### State Management

**Local State (useState)**
- `namespace`: Currently selected namespace
- `selectedPod`: Pod selected in graph for detail view
- Component-level UI state

**Custom Hooks**
- `usePodData`: Manages pod data fetching and state
  - Fetches pods by namespace
  - Handles loading/error states
  - Provides pod expansion toggle
  - Implements refresh functionality

### Data Flow

```
User Action → Component Event Handler → State Update → Re-render
                                     ↓
                                 API Call → Broker → Response
                                     ↓
                            Hook State Update → Component Re-render
```

### API Integration

**Centralized Client (`services/api.ts`)**
- Singleton pattern for HTTP client
- Configurable base URL
- Error handling at client level
- Methods map to Broker endpoints:
  - `/pod/traffic/name/:namespace/:podName`
  - `/pod/syscalls/name/:namespace/:podName`
  - `/pod/ip/:ip`
  - `/health`

### Network Visualization

**React Flow Integration**
1. **Nodes**: Each pod represented as custom `PodNode` component
   - Collapsible with expand/collapse state
   - Shows pod name, namespace, IP
   - Displays connection and syscall counts when expanded

2. **Edges**: Network connections between pods
   - Generated from traffic data
   - Animated flows
   - Width indicates traffic volume
   - Labels show connection count

3. **Layout**: Automatic grid positioning
   - 3 columns
   - Vertical spacing for readability
   - fitView on initial render

### Type Safety

**TypeScript Interfaces**
```typescript
PodInfo          // Pod metadata from K8s
NetworkTraffic   // Network connection data
SyscallInfo      // Syscall usage data
PodNodeData      // Combined pod + UI state
ServiceInfo      // K8s service data
```

**Type-only Imports**
- Uses `import type` for TypeScript types
- Enables `verbatimModuleSyntax` for clean builds
- Prevents runtime type imports

## Styling System

### Tailwind v4 Configuration

**Theme Colors** (defined in `@theme` directive):
```css
--color-hubble-dark: #0E1726
--color-hubble-darker: #0A0F1C
--color-hubble-card: #1A2332
--color-hubble-border: #2A3647
--color-hubble-accent: #3B82F6 (blue)
--color-hubble-success: #10B981 (green)
--color-hubble-warning: #F59E0B (amber)
--color-hubble-error: #EF4444 (red)
```

### React Flow Customization

Custom CSS for graph components:
- Dark background
- Styled controls
- Custom node shadows
- Edge animations

## Performance Considerations

### Optimizations
1. **React Flow**: Virtualized rendering of nodes
2. **Memoization**: useMemo for expensive calculations (edges, nodes)
3. **Callbacks**: useCallback to prevent unnecessary re-renders
4. **Type-only imports**: Smaller bundle size

### Future Improvements
- Virtual scrolling for large data tables
- WebSocket for real-time updates (no polling)
- Service worker for offline support
- Code splitting for route-based loading

## Build Configuration

### Vite Config
- React plugin for JSX transformation
- Fast HMR (Hot Module Replacement)
- Optimized production builds
- CSS minification

### TypeScript Config
- Strict mode enabled
- `verbatimModuleSyntax` for clean imports
- Target: ES2020
- Module: ESNext

### PostCSS
- `@tailwindcss/postcss`: TailwindCSS v4 PostCSS plugin
- `autoprefixer`: Browser compatibility

## Deployment

### Docker Build
Multi-stage Dockerfile:
1. **Build stage**: Node 20 Alpine, npm build
2. **Production stage**: nginx:alpine
   - Serves static files
   - SPA routing configuration
   - Gzip compression
   - Security headers

### Environment Variables
- `VITE_API_URL`: Broker API endpoint
- `VITE_REFRESH_INTERVAL`: Data refresh interval

## Extension Points

### Adding New Features

1. **New API Endpoint**
   - Add method to `BrokerAPIClient` class
   - Define TypeScript interface in `types/index.ts`
   - Use in hook or component

2. **New Visualization**
   - Create component in `components/`
   - Add to NetworkGraph or new container
   - Use React Flow or custom D3.js

3. **New Data Panel**
   - Extend DataTable component
   - Add tab/accordion section
   - Fetch additional data in usePodData hook

4. **Custom Node Type**
   - Create new node component
   - Register in `nodeTypes` object
   - Add type field to node data

## Testing Strategy (Future)

Recommended testing approach:
- **Unit**: Jest + React Testing Library
- **Integration**: Playwright or Cypress
- **E2E**: Against mock Broker API
- **Visual**: Chromatic or Percy

## Security

### Current Measures
- No sensitive data in client code
- Configurable API endpoint (no hardcoded URLs)
- CORS handled by Broker
- nginx security headers in production

### Future Enhancements
- Authentication/authorization
- API key management
- Rate limiting UI
- Content Security Policy
