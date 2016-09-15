'''
Created on September 15, 2016

@author: compsecmonkey

Helper methods for generating API response code and logging the responses.

Usage:
    Utilize the below methods for all return statements in API endpoints
    given the appropriate response.

    Utilize the rfc7231 documentation for determing the appropriate response
    code: https://tools.ietf.org/html/rfc7231#section-6.1

    All helpers will utilize inspect.stack to obtain the calling method's name
    for use with the logging.
'''

import inspect
import json

from flask import Response
from flask import current_app as app


def _finalize_response(data, code):
    resp = Response(response=data,
                    status=code,
                    mimetype="application/json")
    return resp


def prepare_200(data=None):
    function_name = inspect.stack()[1][3]  # gets the calling functions name

    resp_data = {}
    resp_data['code'] = 200
    resp_data['code_name'] = "OK"
    resp_data['function_name'] = function_name
    resp_data['data'] = data

    app.logger.info(resp_data)

    return _finalize_response(json.dumps(resp_data), 200)


def prepare_201(resource):
    function_name = inspect.stack()[1][3]  # gets the calling functions name

    resp_data = {}
    resp_data['code'] = 201
    resp_data['code_name'] = "Created"
    resp_data['function_name'] = function_name
    resp_data['resource'] = resource

    app.logger.info(resp_data)

    return _finalize_response(json.dumps(resp_data), 201)


def prepare_400(error=None):
    function_name = inspect.stack()[1][3]  # gets the calling functions name

    resp_data = {}
    resp_data['code'] = 400
    resp_data['code_name'] = "Bad Request"
    resp_data['function_name'] = function_name
    resp_data['hint'] = str(error)

    app.logger.warning(resp_data)

    return _finalize_response(json.dumps(resp_data), 400)


def prepare_401(user=None, reason=None):
    resp_data = {}
    resp_data['code'] = 401
    resp_data['code_name'] = "Unauthroized"
    resp_data['reason'] = reason

    app.logger.warning(resp_data)

    return _finalize_response(json.dumps(resp_data), 401)



def prepare_404(resource):
    function_name = inspect.stack()[1][3]  # gets the calling functions name

    resp_data = {}
    resp_data['code'] = 404
    resp_data['code_name'] = "Not Found"
    resp_data['function_name'] = function_name
    resp_data['resource'] = str(resource)

    app.logger.warning(resp_data)

    return _finalize_response(json.dumps(resp_data), 404)

def prepare_418():
    resp_data['app_name'] = app_name
    function_name = inspect.stack()[1][3]  # gets the calling functions name

    resp_data = {}
    resp_data['code'] = 418
    resp_data['code_name'] = "I'm A Little Tea Pot" # ;) thanks for reading
    # the code
    resp_data['function_name'] = function_name

    app.logger.info(resp_data)

def prepare_500(error):
    function_name = inspect.stack()[1][3]  # gets the calling functions name

    resp_data = {}
    resp_data['code'] = 500
    resp_data['code_name'] = "Internal Server Error"
    resp_data['function_name'] = function_name
    resp_data['error_type'] = str(type(error))
    resp_data['error_msg'] = str(error)

    app.logger.error(resp_data)

    # If the app is not in debug mode remove the error data... because security
    if not app.config['DEBUG_MODE']:
        resp_data.pop('error_type', None)
        resp_data.pop('error_msg', None)

    return _finalize_response(json.dumps(resp_data), 500)


def prepare_501():
    function_name = inspect.stack()[1][3]  # gets the calling functions name

    resp_data = {}
    resp_data['code'] = 501
    resp_data['code_name'] = "Not Implemented"
    resp_data['function_name'] = function_name

    app.logger.debug(resp_data)

    return _finalize_response(json.dumps(resp_data), 501)
