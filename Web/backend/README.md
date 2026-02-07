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
  "email": "manuel@example.com", 
  "password": "securePassword123",
  "organization": "Example Org",
  "phone": "123-456-7890"
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

### Target Management

**Create Target**
```http
POST /api/target/add-target
Content-Type: application/json
Authorization: Bearer [JWT Token]
{
  "target_name": "Example Target"
  "target_type": domain
  "target_value": scanme.nmap.org
  "public_facing": True
}
```

**List Targets**
```http
GET /api/targets/list-targets
Content-Type: application/json
Authorization: Bearer [JWT Token]
```

### 🔍 Security Scans

**Submit Scan**
```http
POST /api/scans/submit
Content-Type: application/json
Authorization: Bearer [JWT Token]
{
  "target_name": "Example Target",
  "scan_type": "nikto",
}
```
Response: `201 Created` with `scan_job_id`.

**Check Scan Status**
```http
Authorization: Bearer [JWT Token]
GET /api/scans/status/{scan_id}
```
Response: Scan details with status (`pending`, `running`, `completed`, `failed`).

**List user's scans**
```http
Authorization: Bearer [JWT Token]
GET /api/scans/list?status=completed&limit=10
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
Authorization: Bearer [JWT Token]
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
async function registerUser(email, password, organization, phone) {
  const userData = JSON.stringify({
    'email': email,
    'password': password,
    'organization': organization,
    'phone': phone
  });
  await api.post("/auth/register", userData, {
      headers: {
          "Content-Type": "application/json"
      }
  })
  .then(function (response) {
      alert(response.data.message);
      navigate("/")
  }).catch(function (error) {
    if (!error.response)
    {
        alert("Connection error: Please try again later");
    }
    else
    {  
        alert("Registration failed: " + error.response.data.error);
    }
  });
}
```

**Submit security scan**
```javascript
async function submitScan(targetName, scanType) {
  const scanData = JSON.stringify({
    'target_name': targetName,
    'scan_type': scanType
  })
  await api.post('/scans/submit', scanData {
    headers: {
      'Content-Type': 'application/json',
    }
  }).then(function (response) {
    alert(response.data.message);
      navigate("/dashboard")
  }).catch(function (error) {
    if (!error.response)
    {
        alert("Connection error: Please try again later");
    }
    else
    {  
        alert("Scan failed: " + error.response.data.error);
        if (error.response.status === 401){ navigate('/') }
    }
  });
}
```

**Check scan progress**
```javascript
async function checkScanStatus(scanId) {
  await api.get(`/scans/status/${scanId}`)
  .then(function (response) {
    console.log(`Scan ${scanId} status: ${response.data.status}`);
    return scan;
  });
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
  -H "Content-Type: application/json, Authorization: Bearer [JWT Token]" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "testpass123"}'

#Test scan submission
curl -X POST http://localhost:5000/api/scans/submit \
  -H "Content-Type: application/json, Authorization: Bearer [JWT Token]" \
  -d '{"target_name": "Test", "target_type": "domain", "target_value": "example.com", "scan_type": "nmap", "user_id": 1}'
```