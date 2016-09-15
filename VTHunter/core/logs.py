'''
Created on September 15, 2016

@author: compsecmonkey
'''
import logging
from logging.handlers import RotatingFileHandler

from flask import g, request


class LoggingContextFilter(logging.Filter):
    """
    logging filter designed to add the context (IP, username) for the request
    """

    def filter(self, record):
        record.ip = request.remote_addr
        try:
            record.user = g.user_name
        except:
            record.user = None
        return True


def prepare_logger(log_path, log_level):
    logging_handler = RotatingFileHandler(log_path)
    logging_handler.setLevel(log_level)

    logging_format = logging.Formatter(
        "{\"time\":\"%(asctime)s\", \"user\":\" %(user)s \", \"IP\":\" %(ip)s \", \"level\":\"%(levelname)s\", \"msg\":%(message)s}\"")

    logging_handler.setFormatter(logging_format)

    filter = LoggingContextFilter()

    logging_handler.addFilter(filter)

    return logging_handler
