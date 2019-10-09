class Config(object):
    ACCOUNT = 'admin'
    PASSWORD = 'root'


class ProductionConfig(Config):
    DB = '127.0.0.1'
    PORT = 27017
    DBUSERNAME = 'chj'
    DBPASSWORD = 'chj'
    DBNAME = 'xunfeng'
