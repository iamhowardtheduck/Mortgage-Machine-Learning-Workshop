pip install faker elasticsearch --break-system-packages 
python /workspace/workshop/Mortgage-Machine-Learning-Workshop/bootstrap-MLv2-WORKSHOP.py \
  --host http://kubernetes-vm:30920 \
  --user sdg \
  --password changeme \
  --kibana-host http://kubernetes-vm:30002 \
  --no-verify-ssl \
  --skip-ml \
  --dfa-types none
python /workspace/workshop/Mortgage-Machine-Learning-Workshop/sdg-prime-outlier.py \
  --host http://kubernetes-vm:30920 \
  --user sdg \
  --password changeme \
  --no-verify-ssl \
  --days 30 \
  --traces-per-day 5000 \
  --anomaly-chance 0.05 \
  --backfill
