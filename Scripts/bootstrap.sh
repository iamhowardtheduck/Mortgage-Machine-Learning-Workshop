pip install faker elasticsearch --break-system-packages 
python /workspace/workshop/Mortgage-Machine-Learning-Workshop/bootstrap-prime-multilayer.py \
  --host http://kubernetes-vm:30920 \
  --user sdg \
  --password changeme \
  --kibana-host http://kubernetes-vm:30002 \
  --no-verify-ssl \
  --skip-ml \
  --dfa-types none
python /workspace/workshop/Mortgage-Machine-Learning-Workshop/sdg-prime-multilayer.py \
  --host http://kubernetes-vm:30920 \
  --user sdg \
  --password changeme \
  --no-verify-ssl \
  --days 30 \
  --apm-traces-per-day 5000 \
  --edge-events-per-day 20000
  --anomaly-chance 0.05 \
  --bot-attack-chance 0.06 \
  --backfill
