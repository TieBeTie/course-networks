import random
import socket
import threading
from collections import deque
from time import sleep
from protocol_constants import ProtocolConstants

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class MyTCPProtocol(UDPBasedProtocol):
    SYN = ProtocolConstants.SYN
    ACK = ProtocolConstants.ACK
    FIN = ProtocolConstants.FIN
    RTT = ProtocolConstants.RTT
    RST_TIMEOUT = ProtocolConstants.RST_TIMEOUT
    BANDWIDTH = ProtocolConstants.BANDWIDTH
    MSS = ProtocolConstants.MSS
    HEADER = ProtocolConstants.HEADER
    MTU = ProtocolConstants.MTU
    MAX_RETRANSMISSIONS = ProtocolConstants.MAX_RETRANSMISSIONS

    def __init__(self, *args, **kwargs):
        # Инициализация базового класса UDPBasedProtocol с переданными аргументами
        super().__init__(*args, **kwargs)
        
        # Окно передачи данных определяется как количество байт, которое может быть передано за время RTT.
        # BANDWIDTH / 8 переводит полосу пропускания из бит в байты.
        # Умножение на RTT дает количество байт, которое может быть передано за время одного RTT.
        self.window = int(self.BANDWIDTH / 8 * self.RTT)
        
        # Инициализация начальных значений для номеров последовательности и подтверждения
        self.seq = 0  # Номер последовательности для отправляемых данных
        self.ack = 0  # Номер подтверждения для полученных данных
        self.remote_seq = 0  # Номер последовательности, полученный от удаленного узла
        self.remote_ack = 0  # Номер подтверждения, полученный от удаленного узла
        self.retransmissions = 0  # Счетчик переотправлений
        
        # Таймаут устанавливается немного больше, чем RTT, чтобы учесть возможные задержки.
        # 1.1 * RTT позволяет учесть небольшие колебания времени передачи.
        self.timeout = 1.1 * self.RTT
        self.max_retransmissions = self.MAX_RETRANSMISSIONS
        

        # Определение потока для установления соединения.
        # Если локальный порт меньше удаленного, предполагается, что это сервер.
        # В противном случае, это клиент.
        self.establish_thread = None
        if self.udp_socket.getsockname()[1] < self.remote_addr[1]:
            self.establish_thread = threading.Thread(target=self.establish_server)
        else:
            self.establish_thread = threading.Thread(target=self.establish_client)
        # Запуск потока для установления соединения
        self.establish_thread.start()

        # Очередь для хранения отправленных данных
        self.data_sent = deque()
        # Переменная для хранения полученных данных
        self.data_received = bytes()

        # Поток для отправки данных
        self.sending_thread = threading.Thread(target=self.sending)

        # Поток для получения данных
        self.receiving_thread = threading.Thread(target=self.receiving)
        # Флаг для остановки получения данных
        self.stop_receiving = False

        # Событие для обновления данных
        self.updated_data = threading.Event()
        # Событие для обновления подтверждений
        self.updated_ack = threading.Event()

        # Поток для завершения соединения
        self.terminating_thread = None

    def send(self, data: bytes):
        """
        Основной цикл отправки данных включает следующие шаги:
        1. Добавление данных в очередь для отправки.
        2. Запуск потока для отправки данных, если он еще не запущен.
        """
        self.data_sent.appendleft(data)

        if not self.sending_thread.is_alive():
            self.sending_thread = threading.Thread(target=self.sending)
            self.sending_thread.start()

        return len(data)

    def sending(self):
        """
        Основной цикл отправки данных включает следующие шаги:
        1. Получение начального значения seq (sequence number) для отправки данных.
        2. Отправка данных, пока есть данные для отправки.
        3. Обработка ситуаций, когда нет данных для отправки или нет подтверждения от получателя.
        """
        # Дождаться завершения потока установления соединения, если он еще активен
        if self.establish_thread.is_alive():
            self.establish_thread.join()

        # Пока есть данные для отправки
        while self.data_sent:
            start_seq = self.seq  # Сохранить начальное значение seq
            data = self.data_sent.pop()  # Извлечь данные из очереди
            data_length = len(data)  # Определить длину данных
            attempts = 0
            # Пока не получено подтверждение для всех отправленных данных
            while self.remote_ack < start_seq + data_length:
                if (self.seq == self.remote_ack):
                    attempts = 0
                # Проверить, можно ли отправить данные
                can_send = self.seq < self.remote_ack + self.window and self.seq < start_seq + data_length
                if can_send:
                    # Вычислить количество байт для отправки
                    # Мы считаем минимум, чтобы не превысить MSS, окно или оставшиеся данные
                    send_bytes = min(self.MSS, self.remote_ack + self.window - self.seq, start_seq + data_length - self.seq)
                    self.seq += send_bytes  # Обновить seq на количество отправленных байт
                    # Извлечь часть данных для отправки
                    data_chunk = data[self.seq - start_seq - send_bytes:self.seq - start_seq]
                    self.send_data(data_chunk)  # Отправить данные
                else:
                    self.updated_ack.clear()  # Очистить событие обновления ack
                    # Ожидать обновления ack в течение RST_TIMEOUT
                   
                    if not self.updated_ack.wait(self.timeout):
                        attempts += 1
                        if attempts > self.max_retransmissions:
                            return  # Reset connection
                        else:
                            continue # Resend packet
                    self.seq = self.remote_ack  # Обновить seq до последнего подтвержденного значения

    def recv(self, n: int):
        """
        Основной цикл получения данных включает следующие шаги:
        1. Получение данных, пока не получено нужное количество данных.
        2. Обработка ситуаций, когда нет данных для получения или нет подтверждения от отправителя.
        """
        # Проверяем, активен ли поток установления соединения, и ждем его завершения, если это так
        if self.establish_thread.is_alive():
            self.establish_thread.join()

        data = bytes()  # Инициализируем переменную для хранения полученных данных
        not_ack = 0  # Счетчик для отслеживания количества данных, которые не были подтверждены

        # Пока не получено нужное количество данных
        while len(data) < n:
            # Ждем обновления данных в течение заданного таймаута
            if not self.updated_data.wait(self.timeout):
                # Если данных нет, отправляем ACK, чтобы запросить повторную отправку
                self.send_flags(self.ACK)
                not_ack = 0  # Сбрасываем счетчик неподтвержденных данных
                continue  # Переходим к следующей итерации цикла

            self.updated_data.clear()  # Очищаем событие обновления данных
            data_received_length = len(self.data_received) - self.HEADER  # Вычисляем длину полученных данных без заголовка
            expected_seq = self.ack + data_received_length  # Ожидаемое значение последовательности

            # Если ожидаемое значение последовательности совпадает с удаленным значением
            if expected_seq == self.remote_seq:
                # Добавляем полученные данные (без заголовка) к общим данным
                data += self.data_received[self.HEADER:]
                not_ack += data_received_length  # Увеличиваем счетчик неподтвержденных данных
                self.ack = self.remote_seq  # Обновляем значение ack
            elif expected_seq <= self.remote_seq:
                # Если ожидаемое значение последовательности меньше или равно удаленному, отправляем ACK
                self.send_flags(self.ACK)
                not_ack = 0  # Сбрасываем счетчик неподтвержденных данных

            # Если окно меньше или равно количеству неподтвержденных данных, отправляем ACK
            if self.window <= not_ack:
                self.send_flags(self.ACK)
                not_ack = 0  # Сбрасываем счетчик неподтвержденных данных

        # Отправляем три ACK для подтверждения получения данных
        for _ in range(3):
            self.send_flags(self.ACK)

        return data  # Возвращаем полученные данные
    def receiving(self):
        """
        Основной цикл получения данных включает следующие шаги:
        1. Получение данных, пока не получено нужное количество данных.
        2. Обработка ситуаций, когда нет данных для получения или нет подтверждения от отправителя.
        """
        while not self.stop_receiving:
            recv = self.recvfrom(self.MTU)  # Получаем данные с максимальным размером передачи
            packet_type = int.from_bytes(recv[8:10], 'big')

            if packet_type == self.ACK:
                self.remote_ack = max(self.remote_ack, int.from_bytes(recv[4:8], 'big'))
                self.updated_ack.set()  # Устанавливаем событие обновления ack
            elif packet_type == 0:
                self.data_received = recv  # Сохраняем полученные данные
                self.remote_seq = int.from_bytes(recv[0:4], 'big')
                self.updated_data.set()  # Устанавливаем событие обновления данных
            elif packet_type == self.FIN:
                self.terminating_thread = threading.Thread(target=self.terminate_server)
                self.terminating_thread.start()
                break  # Прерываем цикл получения данных

    # Установка соединения клиента
    
    def establish_client(self):
        """
        Процесс установления соединения (рукопожатие) между клиентом и сервером включает следующие шаги:
        1. Клиент генерирует случайное начальное значение seq (sequence number) для уникальности пакетов.
        2. Клиент отправляет серверу пакет с флагом SYN, чтобы инициировать соединение.
        3. Сервер отвечает пакетом с флагами SYN и ACK, подтверждая получение SYN от клиента.
        4. Клиент получает SYN и ACK от сервера и отправляет ACK, завершая установление соединения.
        """
        # Генерация случайного числа для начального значения seq (sequence number) и ack (acknowledgment number)
        # необходима для обеспечения уникальности идентификаторов пакетов в каждом новом соединении.
        # Это помогает избежать конфликтов и путаницы при обработке пакетов, особенно если несколько соединений
        # происходят одновременно или в течение короткого промежутка времени.
        self.seq = random.randint(0, 2 ** 32 - 1)
        self.ack = 0
        # Запуск потока для получения флага SYN и ACK
        thread = threading.Thread(target=self.recv_flags, args=(self.SYN | self.ACK,))
        thread.start()
        # Ожидание завершения потока или истечения таймаута
        while thread.is_alive():
            # Отправка флага SYN
            self.send_flags(self.SYN)
            # Ожидание завершения потока или истечения таймаута
            thread.join(self.timeout)
        self.ack = self.remote_seq
        # Отправка флага ACK
        self.send_flags(self.ACK)
        self.remote_ack = self.seq
        self.remote_seq = self.ack
        self.receiving_thread.start()

    def establish_server(self):
        """
        Процесс установления соединения (рукопожатие) между клиентом и сервером включает следующие шаги:
        1. Сервер генерирует случайное начальное значение seq (sequence number) для уникальности пакетов.
        2. Сервер получает SYN от клиента и отправляет ACK, подтверждая получение SYN.
        3. Клиент получает SYN и ACK от сервера и отправляет ACK, завершая установление соединения.
        """
        self.seq = random.randint(0, 2 ** 32 - 1)
        self.recv_flags(self.SYN)
        self.ack = self.remote_seq

        thread = threading.Thread(target=self.recv_flags, args=(self.ACK,))
        thread.start()
        while thread.is_alive():
            self.send_flags(self.SYN | self.ACK)
            thread.join(self.timeout)

        self.remote_ack = self.seq
        self.remote_seq = self.ack
        self.receiving_thread.start()

    def terminate_client(self):
        """
        Процесс завершения соединения клиента включает следующие шаги:
        1. Клиент отправляет серверу пакет с флагом FIN, чтобы завершить соединение.
        2. Сервер отвечает пакетом с флагами FIN и ACK, подтверждая получение FIN от клиента.
        3. Клиент получает FIN и ACK от сервера и отправляет ACK, завершая соединение.
        """
        self.stop_receiving = True
        # Ожидание завершения потока или истечения таймаута
        while self.receiving_thread.is_alive():
            self.send_flags(self.FIN)
            self.receiving_thread.join(self.timeout)
        
        thread = threading.Thread(target=self.recv_flags, args=(self.FIN | self.ACK,))
        thread.start()
        # Неравенство `self.remote_seq != self.ack + 1` используется для проверки того, что клиент получил
        # подтверждение (ACK) от сервера на отправленный FIN. Если `self.remote_seq` не равно `self.ack + 1`,
        # это означает, что клиент еще не получил подтверждение от сервера, и необходимо продолжать отправлять
        # флаг FIN до тех пор, пока подтверждение не будет получено или не истечет таймаут.
        while thread.is_alive() or self.remote_seq != self.ack + 1:
            self.send_flags(self.FIN)
            thread.join(self.timeout)

        self.ack = self.remote_seq
        
        self.seq += 1
        for _ in range(3):
            self.send_flags(self.ACK)
        # Ждем, пока сервер получит все три подтверждения (ACK)
        # иначе сервер может некорректно завершить соединение.
        sleep(self.timeout)

    def terminate_server(self):
        """
        Процесс завершения соединения сервера включает следующие шаги:
        1. Сервер отправляет клиенту пакет с флагами FIN и ACK, чтобы завершить соединение.
        2. Клиент получает FIN и ACK от сервера и отправляет ACK, завершая соединение.
        """
        if self.sending_thread.is_alive():
            self.sending_thread.join()

        self.seq += 1
        thread = threading.Thread(target=self.recv_flags, args=(self.ACK,))
        thread.start()
        while thread.is_alive() or self.remote_seq != self.ack + 1:
            try:
                self.send_flags(self.FIN | self.ACK)
            except OSError:
                return
            thread.join(self.timeout)

    def send_flags(self, flags):
        """
        Использование 'big' в методах to_bytes и from_bytes указывает на порядок байтов (big-endian).
        В big-endian порядок байтов идет от старшего к младшему, что означает, что старший байт
        находится в начале. Это важно для обеспечения совместимости между различными системами,
        так как некоторые системы могут использовать другой порядок байтов (little-endian).
        """
        self.sendto(self.seq.to_bytes(4, 'big') + self.ack.to_bytes(4, 'big') +
                    flags.to_bytes(2, 'big') + self.window.to_bytes(2, 'big'))

    def send_data(self, data, flags=0):
        self.sendto(self.seq.to_bytes(4, 'big') + self.ack.to_bytes(4, 'big') +
                    flags.to_bytes(2, 'big') + self.window.to_bytes(2, 'big') + data)

    def recv_flags(self, flags):
        """
        Метод recv_flags принимает флаги в качестве аргумента и ожидает получения данных с этими флагами.
        Он использует метод recvfrom для получения данных и проверяет, соответствуют ли полученные флаги
        ожидаемым. Если флаги не совпадают, метод продолжает получать данные до тех пор, пока не получит
        ожидаемые флаги или не возникнет ошибка OSError.
        """
        try:
            self.data_received = self.recvfrom(self.HEADER)
            while int.from_bytes(self.data_received[8:10], 'big') != flags:
                self.data_received = self.recvfrom(self.HEADER)
            self.remote_ack = int.from_bytes(self.data_received[4:8], 'big')
            self.remote_seq = int.from_bytes(self.data_received[0:4], 'big')
        except OSError:
            return

    def close(self):
        """
        Метод close завершает соединение, закрывая сокет и запуская процесс завершения клиента или сервера.
        Он проверяет, запущен ли поток завершения, и если нет, запускает соответствующий процесс.
        """
        if not self.terminating_thread:
            if self.sending_thread.is_alive():
                self.sending_thread.join()
            self.terminating_thread = threading.Thread(target=self.terminate_client)
            self.terminating_thread.start()

        if self.terminating_thread.is_alive():
            self.terminating_thread.join(self.RST_TIMEOUT)
        super().close()