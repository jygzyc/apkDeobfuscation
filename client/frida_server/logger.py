import os
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime

class Logger:
    def __init__(self, log_level='INFO'):
        self.log_level = log_level.upper()

        if not os.path.exists('log'):
            os.mkdir('log')

        self.logger = logging.getLogger('Logger')
        self.logger.setLevel(logging.DEBUG)

        log_file_name = 'log/decryption_%s.log' % (datetime.now().strftime("%Y-%m-%d"))
        self.file_handler = TimedRotatingFileHandler(log_file_name, when="midnight")
        self.file_handler.encoding = 'utf-8'
        self.file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger.addHandler(self.file_handler)

    def debug(self, message):
        if self.log_level == 'DEBUG':
            self.logger.debug(message)

    def info(self, message):
        if self.log_level in ['DEBUG', 'INFO']:
            self.logger.info(message)

    def warning(self, message):
        if self.log_level in ['DEBUG', 'INFO', 'WARNING']:
            self.logger.warning(message)

    def error(self, message):
        if self.log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            self.logger.error(message)

    def critical(self, message):
        if self.log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            self.logger.critical(message)

    def log(self, level, message):
        message = message.encode('unicode_escape').decode('utf-8')
        if isinstance(level, str):
            level = level.upper()
        if level == 'DEBUG':
            self.debug(message)
        elif level == 'INFO':
            self.info(message)
        elif level == 'WARNING':
            self.warning(message)
        elif level == 'ERROR':
            self.error(message)
        elif level == 'CRITICAL':
            self.critical(message)
        else:
            raise ValueError('Invalid log level: {}'.format(level))

    def set_log_level(self, log_level):
        self.log_level = log_level.upper()

if __name__ == '__main__':
    logger = Logger(log_level='DEBUG')
    logger.debug('This is a debug message')
    logger.info('This is an info message')
    logger.warning('This is a warning message')
    logger.error('This is an error message')
    logger.critical('This is a critical message')
    logger.set_log_level('INFO')
    logger.log('debug', 'This is a debug message')
    logger.log('info', 'This is an info message')
    logger.log('warning', 'This is a warning message')
    logger.log('error', 'This is an error message')
    logger.log('critical', 'This is a critical message')
    logger.log('critical', '中文测试')