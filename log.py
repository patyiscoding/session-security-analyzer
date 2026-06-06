# Source - https://stackoverflow.com/a/56944256
# Posted by Sergey Pleshakov, modified by community. See post 'Timeline' for change history
# Retrieved 2026-06-06, License - CC BY-SA 4.0
# Modified

import logging
class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    blue = "\x1b[38;2;0;128;128m"
    purple = "\x1b[38;2;95;95;175m"
    yellow = "\x1b[38;2;215;175;0m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: blue + format + reset,
        logging.INFO: purple + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


log = logging.getLogger("")
log.setLevel(logging.DEBUG)
log.propagate = False

log.handlers.clear()

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
log.addHandler(ch)

logging.getLogger("mitmproxy").setLevel(logging.WARNING)