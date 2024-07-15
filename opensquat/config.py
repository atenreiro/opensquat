import configparser

def read_config(file_name):

    config = configparser.ConfigParser()
    config.read(file_name)

    # Reading values from API section
    API = config['API']['API']

    # Reading values from Options section
    VERBOSE = config['Options'].getboolean('VERBOSE')
    UPDATE = config['Options'].getboolean('CHECK_UPDATE')
    OPEN_PORT = config.get('Options', 'OPEN_PORTS', fallback='80,443').split(',')

    # Reading values from Logging section
    log_file = config['Logging']['LogFile']
    log_level = config['Logging']['LogLevel']

    return {
        "API": API,
        "Verbose": VERBOSE,
        "Update": UPDATE,
        "Open_Ports": OPEN_PORT,
        "Logging": {
            "LogFile": log_file,
            "LogLevel": log_level
        }
    }