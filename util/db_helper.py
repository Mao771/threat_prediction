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

    def write(self, points, **kwargs):
        self.db_client.write_points(points, **kwargs)

    def get(self, measurements, aggregation, fields):
        str_fields = ','.join(fields)
        str_query = 'SELECT {} FROM {} {}'.format(str_fields, measurements, aggregation)
        result = pd.DataFrame(self.db_client.query(str_query).get_points())
        return result

    def drop(self, measurement):
        self.db_client.drop_measurement(measurement)
