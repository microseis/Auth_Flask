import logging.config

# generate log
logger = logging.getLogger()

# log level
logger.setLevel(logging.INFO)

#  log formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# log to console
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
