# 🧹 AWS AMI & Snapshot Cleanup Script

This Python script was created as part of a cost-saving exercise for a client who had accumulated a large number of unused Amazon Machine Images (AMIs) and associated EBS snapshots. Manually cleaning them up via the AWS Console would have been time-consuming and error-prone — so I automated the process using **Boto3**.

---

## 🔁 Script Workflow

1. Read a list of AMI IDs from a `.txt` file  
2. Use Boto3 to:
   - Deregister each AMI
   - Identify associated snapshots
   - Delete the snapshots  
