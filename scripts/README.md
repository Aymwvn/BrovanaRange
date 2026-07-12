# RedRange Automation Scripts

Run `cleanup_expired_labs.py` from inside the backend container or any environment that has the backend dependencies and `.env` configured:

```bash
python /app/scripts/cleanup_expired_labs.py
```

For an operator workstation, `cleanup-expired-labs.ps1` calls the secured admin API:

```powershell
$env:REDRANGE_ADMIN_ACCESS_TOKEN = "<admin access token>"
.\scripts\cleanup-expired-labs.ps1 -ApiBase http://localhost:8000
```
