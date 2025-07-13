import frida
import json
import os
import re
from flask import Flask, request, make_response
from logger import Logger
from config import Config

class FridaServer:
    """
    A server that uses Frida to hook into a running Android application
    and provides a Flask API to trigger and retrieve deobfuscated data.
    """
    def __init__(self):
        self.logger = Logger(log_level="INFO")
        self.config = Config.builder()
        self.app = self._create_flask_app()
        self.script = self._initialize_frida()
        self.method_handlers = self._register_handlers()

    def _create_flask_app(self):
        """Initializes the Flask application and its routes."""
        app = Flask(__name__)

        @app.route('/decrypt', methods=['POST'])
        def decrypt_route():
            data = request.get_data()
            try:
                json_data = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                self.logger.error(f"Failed to decode request data: {e}")
                return make_response("Invalid JSON format", 400)

            self.logger.info(f"Received request: {json_data}")
            method_sig = json_data.get("method")
            method_param = self._handle_params(json_data.get("param"))
            self.logger.debug(f"method: {method_sig}; params: {method_param}")

            handler = self.method_handlers.get(method_sig)
            if not handler:
                self.logger.warning(f"No handler found for method: {method_sig}")
                return make_response(f"No handler for method: {method_sig}", 404)

            res = self._process_string(handler(method_sig, method_param))
            response = make_response(res, 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        return app

    def _initialize_frida(self):
        """Connects to the Frida server and injects the script."""
        try:
            self.logger.info(f"Connecting to device: {self.config.remote_device}")
            device = frida.get_device_manager().add_remote_device(self.config.remote_device)

            target = self.config.package_name if self.config.spawn else self.config.app_name
            self.logger.info(f"Targeting: {target} (Spawn: {self.config.spawn})")

            if self.config.spawn:
                pid = device.spawn(self.config.package_name)
                session = device.attach(pid)
                device.resume(pid)
            else:
                session = device.attach(self.config.app_name)

            script_path = os.path.join(os.path.dirname(__file__), "scripts", self.config.frida_script_name)
            self.logger.info(f"Loading script: {script_path}")
            with open(script_path) as f:
                js_code = f.read()

            script = session.create_script(js_code)
            script.on("message", self._on_frida_message)
            script.load()
            self.logger.info("Frida script loaded successfully.")
            return script
        except frida.ServerNotRunningError:
            self.logger.error(f"Frida server not running on {self.config.remote_device}. Please ensure it's started.")
            exit(1)
        except frida.ProcessNotFoundError:
            self.logger.error(f"Process '{self.config.app_name}' not found. Is the app running?")
            exit(1)
        except Exception as e:
            self.logger.error(f"An unexpected Frida error occurred: {e}")
            exit(1)

    def _register_handlers(self):
        """Maps method signatures from config to handler functions."""
        handlers = {}
        for sig, func_name in self.config.methods_map.items():
            handler_func = getattr(self, func_name, None)
            if handler_func and callable(handler_func):
                handlers[sig] = handler_func
                self.logger.debug(f"Registered handler '{func_name}' for '{sig}'")
            else:
                self.logger.warning(f"Handler function '{func_name}' not found for signature '{sig}'")
        return handlers

    def _on_frida_message(self, message, data):
        """Callback for messages from the Frida script."""
        if message['type'] == 'send':
            self.logger.debug(f"[*] Frida Message: {message['payload']}")
        else:
            self.logger.debug(message)

    def _process_string(self, s: str) -> str:
        """Cleans up whitespace from the returned string."""
        return " ".join(str(s).split())

    def _handle_params(self, params):
        """Allows custom parameter processing. Default is no-op."""
        return params

    #################### Method Handlers ####################
    # Method handler function names must match the values in the
    # `methods_map` of your config.json.

    def _handle_qz_b(self, method_name, method_param):
        res = self.script.exports_sync.invokemethod01(method_param)
        self.logger.info(f"Decrypted '{method_param}' to '{res}'")
        return res

    def _handle_cg_b(self, method_name, method_param):
        res = self.script.exports_sync.invokemethod02(method_param)
        self.logger.info(f"Decrypted '{method_param}' to '{res}'")
        return res

    def run(self):
        """Starts the Flask server."""
        self.logger.info(f"Starting Flask server on http://0.0.0.0:5000")
        self.app.run(host="0.0.0.0", port=5000, debug=False)

def main():
    """Main entry point to instantiate and run the server."""
    server = FridaServer()
    server.run()

if __name__ == "__main__":
    main()
