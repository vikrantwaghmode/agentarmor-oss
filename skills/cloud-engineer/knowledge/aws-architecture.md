# AWS Architecture Patterns

## Well-Architected Framework Pillars
1. **Operational Excellence** — runbooks, IaC, small reversible changes, frequent small deployments
2. **Security** — identity foundation, traceability, protect all layers, automate security
3. **Reliability** — recover from failure, horizontal scaling, stop guessing capacity
4. **Performance Efficiency** — use managed services, go global in minutes, experiment
5. **Cost Optimisation** — adopt consumption model, measure efficiency, avoid undifferentiated heavy lifting
6. **Sustainability** — right-size, use efficient data paths, maximise utilisation

## Common Patterns

### Serverless Web App
```
Route 53 → CloudFront → S3 (static assets)
                       → API Gateway → Lambda → DynamoDB / RDS
```

### Container-Based Service
```
ALB → ECS Fargate / EKS → ECR images → RDS (private subnet)
           ↓
     Secrets Manager (credentials)
     CloudWatch (logs, metrics, alarms)
```

### Event-Driven Processing
```
S3 event / SQS → Lambda → DynamoDB / SNS → downstream consumers
```

## Security Baseline
- Never use root account for daily work; MFA on all users
- IAM roles for services (not access keys); least-privilege policies
- VPC: public subnet for ALB only; private subnets for compute and DB
- S3: block public access by default; bucket policies over ACLs
- Encryption: KMS-managed keys for S3, RDS, EBS, Secrets Manager
- CloudTrail enabled in all regions; Config rules for drift detection

## Cost Levers
- Right-size EC2 with Compute Optimizer; use Graviton instances (20% cheaper)
- Reserved Instances / Savings Plans for steady-state workloads (up to 72% discount)
- Spot Instances for batch / fault-tolerant workloads
- S3 lifecycle policies: move to Glacier after 90 days
- Data transfer: keep traffic within AZ or use VPC endpoints
