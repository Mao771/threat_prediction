from PfsenseFauxapi.PfsenseFauxapi import PfsenseFauxapi
import configparser


class ApiHelper:
    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.api_config = self.config['FauxApi']
        self.fauxapi = PfsenseFauxapi(self.api_config['APIHost'], self.api_config['APIKey'],
                                      self.api_config['APISecret'])
        self.pfSense_config = self.fauxapi.config_get()
        self.pfSense_host = self.pfSense_config['system']['hostname'] + "." + self.pfSense_config['system']['domain']

    def fauxapi_function_call(self, functionName):
        """Call fauxapi function_call without function arguments"""
        data = {
            "function": functionName
        }
        return self.fauxapi.function_call(data)['data']['return']

    def fauxapi_function_call_args(self, functionName, args):
        """Call fauxapi function_call function with arguments"""
        data = {
            "function": functionName,
            "args": args
        }
        return self.fauxapi.function_call(data)['data']['return']

    def gateway_status(self):
        """Get and save information about statuses of gateways."""
        gateways = self.fauxapi_function_call_args("return_gateways_status", "true")
        result = []

        for gateway in gateways:
            gateway_status = 1 if gateways[gateway]['status'] == "none" else 0
            gateway_data = [
                {
                    "measurement": "gateway_status",
                    "fields": {
                        "name": gateways[gateway]['name'],
                        "rtt": gateways[gateway]['delay'],
                        "rttsd": gateways[gateway]['stddev'],
                        "status": gateway_status
                    },
                    "tags": {
                        "host": self.pfSense_host
                    }
                }
            ]
            result.append(gateway_data)

        return result

    def interface_statistics(self):
        """Get and save information about interfaces statistics."""
        interface_descriptions = self.fauxapi_function_call("get_configured_interface_with_descr")
        result = []
        for interface in interface_descriptions:
            interface_info = self.fauxapi_function_call_args("get_interface_info", interface)
            interface_data = [
                {
                    "measurement": "interface_statistics",
                    "fields": {
                        "bytes_in": interface_info['inbytes'],
                        "bytes_out": interface_info['outbytes'],
                        "collisions": interface_info['collisions'],
                        "errors_in": interface_info['inerrs'],
                        "errors_out": interface_info['outerrs'],
                        "name": interface_descriptions[interface],
                        "packets_in": interface_info['inpkts'],
                        "packets_out": interface_info['outpkts']
                    },
                    "tags": {
                        "host": self.pfSense_host,
                        "interface": interface_info['if']
                    }
                }
            ]
            result.append(interface_data)

        return result
