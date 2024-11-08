import logging
import os

class TCPLogger:
    def __init__(self, debug=False, log_file='tcp_protocol.log'):
        self.debug = debug
        if self.debug:
            self.logger = logging.getLogger('tcp_protocol')
            self.logger.setLevel(logging.DEBUG)
            
            # Создаем форматтер для логов
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
            )
            
            # Хендлер для файла
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            
            # Хендлер для консоли
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
    def debug(self, msg):
        if self.debug:
            self.logger.debug(msg)
            
    def info(self, msg):
        if self.debug:
            self.logger.info(msg)
            
    def warning(self, msg):
        if self.debug:
            self.logger.warning(msg)
            
    def error(self, msg):
        if self.debug:
            self.logger.error(msg)
