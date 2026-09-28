# IMPORTANT: keep workers = 1 so the in-memory sliding windows
# and the APScheduler job stay consistent inside a single process.
workers = 1
threads = 4
bind = "0.0.0.0:8000"
timeout = 120
accesslog = "-"
errorlog = "-"