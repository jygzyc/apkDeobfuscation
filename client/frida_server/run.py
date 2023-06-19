import frida
import json
import os
import re
import shutil
from flask import Flask, request, make_response
from logger import Logger
from config import Config

app = Flask(__name__)
logger = Logger(log_level="INFO")

def message(message, data):
    if message['type'] == 'send':
        logger.debug(f"[*] {message['payload']}")
    else:
        logger.debug(message)

@app.route('/decrypt', methods=['POST'])#data解密
def decrypt_class():
    data = request.get_data()
    json_data = json.loads(data.decode("utf-8"))
    logger.info(json_data)
    method_sig = json_data.get("method")
    method_param = handle_params(json_data.get("param"))
    logger.debug(f"method: ${method_sig}; params: ${method_param}") 
    handle_method = globals()[methods[method_sig]]
    res = _process_string(handle_method(method_sig, method_param))
    response = make_response(res, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

def _process_string(s: str) -> str:
    '''
    Remove consecutive line breaks and spaces from a string, 
    while keeping leading and trailing spaces.
    '''
    s = ' '.join(s.split())
    s = re.sub(r'\s+', ' ', s)
    if len(s) > 0 and s[0] == ' ':
        s = ' ' + s.lstrip()
    if len(s) > 0 and s[-1] == ' ':
        s = s.rstrip() + ' '
    return s

def handle_params(params):
    '''
    Allow custom parameter processing functions.
    '''
    return params

#################### Method Handler ####################

def _handle_qz_b(method_name, method_param):
    res = _process_string(script.exports_sync.invokemethod01(method_param))
    logger.info(f"{method_param} => {res}")
    return res

def _handle_cg_b(method_name, method_param):
    res = _process_string(script.exports_sync.invokemethod02(method_param))
    logger.info(f"{method_param} => {res}")
    return res

#################### Flask Server ####################

config = Config.builder()
methods = config.methods_map

device = frida.get_device_manager().add_remote_device(config.remote_device)
if(config.spawn):
    session = device.spawn(config.package_name)
else:
    session = device.attach(config.app_name)

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", config.frida_script_name)) as f:
    jsCode = f.read()

script = session.create_script(jsCode)
script.on("message",message)
script.load()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)