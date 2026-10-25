# Production PHP 8.4.26 Compose target

Starts `php:8.4.26-apache` with the image's stock `php.ini-production`
activated inside the container. No host PHP configuration is mounted.

```bash
cd lab/prod-8426
chmod 0777 out
sudo docker compose up -d
curl -sS http://127.0.0.1:1337/index.php
```

From the repository root:

```bash
python3 production_exploit.py --port 1337 --workers 150 \
    --host-proof lab/prod-8426/out/p1
```

The target uses the official prefork MPM with 150 workers. The proof file
appears in `out/p1`. Stop with:

```bash
cd lab/prod-8426
sudo docker compose down
```
