from influxdb import InfluxDBClient
import pandas as pd
import configparser


class DbHelper:
    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.db_config = self.config['InfluxDB']
        self.db_client = InfluxDBClient(self.db_config['Host'], self.db_config['Port'],
                                        self.db_config['User'], self.db_config['Password'],
                                        self.db_config['Db'])

    def write(self, df):
        self.db_client.write_points(df)

    def __normalize_measurement(self, interface_data):
        tags = interface_data.get('tags')
        fields = interface_data.get('fields')
        interface = tags and tags.get('interface')
        last_measurement = self.db_client.query(
            'SELECT last(bytes_in), * FROM interface_statistics WHERE interface=\'{}\''.format(interface))
        result_points = last_measurement.get_points()

        for point in result_points:
            for k, v in point.items():
                if k not in ['time', 'last'] and not type(v) is str and fields[k] > v:
                    try:
                        fields[k] -= v
                    except:
                        pass
            break

    def get(self, measurements, aggregation, fields):
        str_fields = ','.join(fields)
        str_query = 'SELECT {} FROM {} {}'.format(str_fields, measurements, aggregation)
        result = pd.DataFrame(self.db_client.query(str_query).get_points())
        return result
