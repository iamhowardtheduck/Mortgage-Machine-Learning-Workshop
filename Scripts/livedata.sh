python /workspace/workshop/Mortgage-Machine-Learning-Workshop/sdg-prime-outlier.py \
  --host http://kubernetes-vm:30920 \
  --user sdg \
  --password changeme \
  --no-verify-ssl \
  --traces-per-day 5000 \
  --anomaly-chance 0.05 \
  --live-only 
