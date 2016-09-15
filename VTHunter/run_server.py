'''
Created on September 15, 2016

@author: compsecmonkey
'''

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException, default_exceptions

from core.logs import prepare_logger
from config import Config

from api.responses import prepare_200

app = None


def make_json_app(import_name, **kwargs):
    '''
    Creates a JSON-oriented Flask app.
    All error responses that you don't specifically
    manage yourself will have application/json content
    type, and will contain JSON like this (just an example):
    { "message": "405: Method Not Allowed" }
    '''

    def make_json_error(ex):
        response = jsonify(message=str(ex))
        response.status_code = (ex.code
                                if isinstance(ex, HTTPException)
                                else 500)
        return response

    app = Flask(import_name, **kwargs)

    for code in default_exceptions:
        app.error_handler_spec[None][code] = make_json_error

    return app

'''
Begin App Building
'''
# Load Config
config = Config()

# build the app
app = make_json_app(__name__)
app.config.from_object(config)

# logging
logger = prepare_logger(app.config['LOGGING_PATH'], app.config['LOGGING_LEVEL'])
app.logger.addHandler(logger)


'''
End App Building
'''


@app.route('/')
def hello_dog():
    return prepare_200("Hello, This is Dog")


if __name__ == '__main__':
    app.run(debug=app.config['DEBUG_MODE'], port=app.config['API_PORT'])