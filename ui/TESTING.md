# UI Testing Guide

## Current Status

The UI is now running at **http://localhost:5173** and properly configured to connect to the Broker API.

## What Has Been Fixed

### 1. API Integration
- ✅ Updated TypeScript types to match Broker's data structures exactly
- ✅ Fixed API endpoints to use correct paths:
  - `/pod/info` - Get all pods
  - `/pod/traffic/{name}` - Get traffic by pod name
  - `/pod/syscalls/{name}` - Get syscalls by pod name
  - `/pod/ip/{ip}` - Get pod by IP
  - `/svc/ip/{ip}` - Get service by IP
  - `/health` - Health check

### 2. Data Structure Alignment

**PodInfo** (matches broker's `PodDetail`):
```typescript
{
  pod_name: string;
  pod_ip: string;
  pod_namespace: string | null;
  pod_obj?: any;
  time_stamp: string;
}
```

**NetworkTraffic** (matches broker's `PodTraffic`):
```typescript
{
  uuid: string;
  pod_name: string | null;
  pod_namespace: string | null;
  pod_ip: string | null;
  pod_port: string | null;
  ip_protocol: string | null;
  traffic_type: string | null;  // 'ingress' or 'egress'
  traffic_in_out_ip: string | null;
  traffic_in_out_port: string | null;
  time_stamp: string;
}
```

**SyscallInfo** (matches broker's `PodSyscalls`):
```typescript
{
  pod_name: string;
  pod_namespace: string;
  syscalls: string;  // Comma-separated string
  arch: string;
  time_stamp: string;
}
```

### 3. UI Component Updates
- ✅ NetworkGraph: Generates edges based on traffic_type (ingress/egress)
- ✅ DataTable: Shows traffic with proper pod/remote IP columns
- ✅ DataTable: Parses syscalls from comma-separated string
- ✅ usePodData hook: Fetches from `/pod/info` and filters by namespace

## Testing Without Broker

Since the Broker is not currently running, the UI will:
1. Show the loading spinner
2. Attempt to connect to http://localhost:9090
3. Display "No pods found" or connection error
4. UI components and layout should still be visible and functional

## Testing With Broker

To fully test the UI, you need:

### 1. Start the Broker
```bash
# From project root
cd broker
DATABASE_URL=postgres://user:pass@localhost:5432/kguardian cargo run
```

### 2. Ensure Data Exists
The Broker database should have:
- Pod details in `pod_details` table
- Network traffic in `pod_traffic` table
- Syscalls in `pod_syscalls` table

### 3. Test Scenarios

#### Scenario 1: View All Pods
1. Open http://localhost:5173
2. Select namespace from dropdown (default: "default")
3. Verify pods appear as nodes in the graph
4. Check that node count in footer matches actual pods

#### Scenario 2: Expand/Collapse Pods
1. Click the +/- button on any pod node
2. Verify the node expands to show:
   - Pod IP address
   - Connection count
   - Syscall count (if available)
3. Click again to collapse

#### Scenario 3: View Pod Details
1. Click on any pod node in the graph
2. Verify the bottom table populates with:
   - Pod information (name, namespace, IP)
   - Network traffic table showing:
     - Traffic type (ingress/egress)
     - Pod IP and port
     - Remote IP and port
     - Protocol
     - Timestamp
   - Syscalls section (if data exists):
     - Architecture
     - List of syscalls (showing first 10, with "+X more" if >10)
     - Timestamp

#### Scenario 4: Network Graph Visualization
1. Verify edges (arrows) connect pods with traffic
2. Check edge thickness correlates to traffic volume
3. Verify edges are animated
4. Verify edge labels show connection count
5. Check that ingress/egress traffic creates proper directional edges

#### Scenario 5: Namespace Switching
1. Change namespace in dropdown
2. Verify graph updates with pods from new namespace
3. Check that footer updates pod count
4. Confirm refresh button works

#### Scenario 6: Error Handling
1. Stop the Broker
2. Click refresh in UI
3. Verify error message displays
4. Restart Broker
5. Click refresh
6. Verify data loads successfully

## API Call Verification

Open browser DevTools (F12) → Network tab to verify:

1. **Initial Load**:
   - GET http://localhost:9090/pod/info
   - GET http://localhost:9090/pod/traffic/{pod_name} (for each pod)
   - GET http://localhost:9090/pod/syscalls/{pod_name} (for each pod)

2. **Namespace Change**:
   - Same calls as above, but filters client-side

3. **Refresh Button**:
   - Repeats all API calls

## Expected API Responses

### GET /pod/info
```json
[
  {
    "pod_name": "frontend-app-abc123",
    "pod_ip": "10.0.1.10",
    "pod_namespace": "default",
    "pod_obj": { ... },
    "time_stamp": "2025-10-27T10:00:00"
  }
]
```

### GET /pod/traffic/frontend-app-abc123
```json
[
  {
    "uuid": "uuid-1234",
    "pod_name": "frontend-app-abc123",
    "pod_namespace": "default",
    "pod_ip": "10.0.1.10",
    "pod_port": "8080",
    "ip_protocol": "TCP",
    "traffic_type": "egress",
    "traffic_in_out_ip": "10.0.1.20",
    "traffic_in_out_port": "5432",
    "time_stamp": "2025-10-27T10:05:00"
  }
]
```

### GET /pod/syscalls/frontend-app-abc123
```json
[
  {
    "pod_name": "frontend-app-abc123",
    "pod_namespace": "default",
    "syscalls": "read,write,open,close,socket,connect,sendto,recvfrom",
    "arch": "x86_64",
    "time_stamp": "2025-10-27T10:00:00"
  }
]
```

## Configuration

### Change Broker URL
Edit `ui/src/services/api.ts`:
```typescript
const apiClient = new BrokerAPIClient('http://your-broker-url:9090');
```

Or set environment variable:
```bash
VITE_API_URL=http://your-broker-url:9090 npm run dev
```

## Known Limitations

1. **No Real-time Updates**: UI requires manual refresh
   - Future: Implement WebSocket for live updates

2. **No Pagination**: Loads all pods at once
   - Future: Add pagination or virtual scrolling for large clusters

3. **Limited Namespace List**: Hardcoded namespace options
   - Future: Fetch namespaces from Kubernetes API

4. **External Traffic**: Only shows pod-to-pod traffic within namespace
   - External IPs won't have corresponding nodes
   - Future: Add "external" nodes for outside traffic

## Troubleshooting

### Issue: "CORS Error"
**Solution**: Broker needs CORS headers configured. Add to broker:
```rust
// In broker main.rs or middleware
App::new()
    .wrap(
        Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
    )
```

### Issue: "ERR_CONNECTION_REFUSED"
**Solution**:
1. Check Broker is running: `curl http://localhost:9090/health`
2. Verify port 9090 is not blocked by firewall
3. Check DATABASE_URL is set correctly

### Issue: "No pods showing"
**Solution**:
1. Verify pods exist in database: `SELECT * FROM pod_details;`
2. Check namespace filter matches pod data
3. Look at browser console for API errors

### Issue: "Build errors"
**Solution**:
```bash
cd ui
rm -rf node_modules package-lock.json
npm install
npm run build
```

## Performance Testing

For large clusters:
1. Test with 10+ pods
2. Test with 100+ traffic records
3. Monitor browser memory usage
4. Check graph rendering performance
5. Verify table scrolling is smooth

## Next Steps

After basic testing works:
1. Deploy Broker to Kubernetes
2. Deploy UI as Kubernetes service
3. Configure ingress for external access
4. Add authentication/authorization
5. Implement WebSocket for real-time updates
6. Add time-range filtering
7. Add export functionality
