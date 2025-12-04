# Cyber Clinic backend api

## Notes for frontend coders

This backend provides REST API endpoints for the cyber clinic web application. All endpoints return JSON and expect JSON input where applicable.

**Base URL**: `http://localhost:5000`

## Quick Start for Frontend

1. **Start the backend server**
   ```bash
   cd Web/backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 main.py
   ```

2. **Test connection**
   ```bash
   curl http://localhost:5000/
   # Should return: {"status": "running", "service": "cyber-clinic-backend"}
   ```

## API Endpoints for frontend

### Authentication

**Register user**
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "manuel",
  "email": "manuel@example.com", 
  "password": "securePassword123"
}
```
Response: `201 Created` with user data, or `409 Conflict` if user exists.

**Login User**
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "manuel",
  "password": "securePassword123"
}
```
Response: `200 OK` with user session, or `401 Unauthorized`.

### 🔍 Security Scans

**Submit Scan**
```http
POST /api/scans/submit
Content-Type: application/json

{
  "target_name": "My Website",
  "target_type": "domain",
  "target_value": "example.com",
  "scan_type": "nmap",
  "user_id": 1
}
```
Response: `201 Created` with `scan_job_id`.

**Check Scan Status**
```http
GET /api/scans/status/{scan_id}
```
Response: Scan details with status (`pending`, `running`, `completed`, `failed`).

**List user's scans**
```http
GET /api/scans/list?user_id=1&status=completed&limit=10
```
Response: Array of scan jobs.

### Reports

**Generate report**
```http
POST /api/reports/generate/{scan_id}
Content-Type: application/json

{
  "format": "html"
}
```
Response: `201 Created` with download URL.

**Download report**
```http
GET /api/reports/download/{scan_id}
```
Response: File download (PDF/HTML).

### System status

**Health check**
```http
GET /
```

**API info**
```http
GET /api/info
```

## Frontend integration examples

### JavaScript/Fetch api

**User Registration**
```javascript
async function registerUser(username, email, password) {
  const response = await fetch('http://localhost:5000/api/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, email, password })
  });
  
  if (response.ok) {
    const user = await response.json();
    console.log('User registered:', user);
    return user;
  } else {
    const error = await response.json();
    console.error('Registration failed:', error);
  }
}
```

**Submit security scan**
```javascript
async function submitScan(targetName, targetType, targetValue, scanType, userId) {
  const response = await fetch('http://localhost:5000/api/scans/submit', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      target_name: targetName,
      target_type: targetType,
      target_value: targetValue,
      scan_type: scanType,
      user_id: userId
    })
  });
  
  if (response.ok) {
    const result = await response.json();
    console.log('Scan submitted:', result);
    return result.scan_job_id;
  }
}
```

**Check scan progress**
```javascript
async function checkScanStatus(scanId) {
  const response = await fetch(`http://localhost:5000/api/scans/status/${scanId}`);
  const scan = await response.json();
  
  console.log(`Scan ${scanId} status: ${scan.status}`);
  return scan;
}
```

## Data formats

### Scan types
- `"nmap"` - Basic port scan
- `"vulnerability"` - Vulnerability assessment
- `"full"` - Comprehensive scan

### Target types  
- `"domain"` - Domain name ("example.com")
- `"ip"` - IP address ("192.168.1.1")
- `"range"` - IP range in CIDR ("192.168.1.0/24")

### Scan status values
- `"pending"` - Scan submitted, waiting to start
- `"running"` - Scan currently executing
- `"completed"` - Scan finished successfully
- `"failed"` - Scan encountered an error
- `"cancelled"` - Scan was cancelled by user

## Testing the api

```bash
#Test backend is running
curl http://localhost:5000/

#Test user registration
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "testpass123"}'

#Test scan submission
curl -X POST http://localhost:5000/api/scans/submit \
  -H "Content-Type: application/json" \
  -d '{"target_name": "Test", "target_type": "domain", "target_value": "example.com", "scan_type": "nmap", "user_id": 1}'
```