bind = "0.0.0.0:" + str(int(__import__("os").environ.get("PORT", "8080")))
workers = 2
threads = 2
timeout = 60
graceful_timeout = 30
keepalive = 5
