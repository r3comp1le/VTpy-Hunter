import logging


class Config(object):
    # Global Config Variable:
    DEBUG_MODE = False
    LOGGING_PATH = '/var/log/vt_hunter.log'
    LOGGING_LEVEL = logging.INFO

    #API Specific:
    API_PORT = 5000

    # Mongo Config
    MONGODB_HOST = "127.0.0.1"
    MONGODB_PORT = 27017
    MONGODB_DB_NAME = "vt_hunter"

    # VT Config
    # TODO: need to have some quick documentation comments on these values
    VT_INTEL = True
    VT_INTEL_KEY = ""
    VT_MASS = True
    VT_MASS_KEY = ""
    VT_DELETE = False
    VT_FILE_DIRECTORY = "/tmp"

    # Cuckoo Analysis Module
    CUCKOO_ENABLED = True
    CUCKOO_MODULE = "cuckoo"
    CUCKOO_CLASS = "CuckooAnalysis"