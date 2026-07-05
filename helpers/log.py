# Source - https://stackoverflow.com/a/56944256
# Posted by Sergey Pleshakov, modified by community. See post 'Timeline' for change history
# Retrieved 2026-06-06, License - CC BY-SA 4.0
# Modified
import logging

METADATA = 5
logging.addLevelName(METADATA, "METADATA")

def metadata(self, message, *args, **kwargs):
    if self.isEnabledFor(METADATA):
        self._log(METADATA, message, args, **kwargs)

logging.Logger.metadata = metadata
logging.METADATA = METADATA


HASHCAT = 8
logging.addLevelName(HASHCAT, "HASHCAT")

def hashcat(self, message, *args, **kwargs):
    if self.isEnabledFor(HASHCAT):
        self._log(HASHCAT, message, args, **kwargs)

logging.Logger.hashcat = hashcat
logging.HASHCAT = HASHCAT



class CustomFormatter(logging.Formatter):
    orange = "\x1b[38;2;191;136;26m"
    grey = "\x1b[38;20m"
    blue = "\x1b[38;2;0;128;128m"
    purple = "\x1b[38;2;95;95;175m"
    yellow = "\x1b[38;2;245;212;0m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.HASHCAT: orange + format + reset,
        logging.METADATA: grey + format + reset,
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
log.setLevel(logging.METADATA)
log.propagate = False

log.handlers.clear()

ch = logging.StreamHandler()
ch.setLevel(logging.METADATA)
ch.setFormatter(CustomFormatter())
log.addHandler(ch)

logging.getLogger("mitmproxy").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)