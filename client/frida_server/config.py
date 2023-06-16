import json
import os

class Config:
    def __init__(self, remote_device, spawn, package_name, app_name, frida_script_name, methods_map):
        self.remote_device = remote_device
        self.spawn = spawn
        self.package_name = package_name
        self.app_name = app_name
        self.frida_script_name = frida_script_name
        self.methods_map = methods_map

    @classmethod
    def builder(cls):
        config_file = 'config.json'

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)) as f:
            config_json = json.load(f)

        return cls(
            remote_device=config_json['remote_device'],
            spawn = config_json['spawn'],
            package_name=config_json['package_name'],
            app_name=config_json['app_name'],
            frida_script_name=config_json['frida_script_name'],
            methods_map=config_json['methods_map']
        )