import socket
import threading
from collections import deque
from time import sleep
from protocol_logger import TCPLogger


class ProtocolConstants:
    """
    Класс, содержащий константы, используемые в протоколе.
    """
    SYN = 0b10           # Флаг SYN для установки соединения
    ACK = 0b10000        # Флаг ACK для подтверждения
    FIN = 0b1            # Флаг FIN для завершения соединения
    RTT = 0.01           # Время задержки (Round-Trip Time) в секундах
    RST_TIMEOUT = 1      # Таймаут для сброса соединения в секундах
    BANDWIDTH = 1_000_000  # Полоса пропускания в битах в секунду
    MSS = 1460           # Максимальный размер сегмента в байтах
    HEADER = 12          # Размер заголовка в байтах
    MTU = MSS + HEADER    # Максимальный размер передачи (Maximum Transmission Unit) в байтах


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
    def __init__(self, *args, debug=True, **kwargs):
        """
        Реализация TCP-подобного протокола поверх UDP.
        
        Обеспечивает:
        - Установление соединения через three-way handshake
        - Надежную передачу данных с подтверждениями
        - Управление потоком через скользящее окно
        - Корректное закрытие соединения
        
        Параметры:
        - local_addr: кортеж (хост, порт) для локального адреса
        - remote_addr: кортеж (хост, порт) для удаленного адреса  
        - debug: флаг для включения логирования (по умолчанию True)
        """
        super().__init__(*args, **kwargs)
        self.logger = TCPLogger(debug=debug)
        self.constants = ProtocolConstants()
        self.window_size = int(self.constants.BANDWIDTH / 8 * self.constants.RTT)
        self.sequence_number = 0
        self.ack_number = 0
        self.remote_sequence_number = 0
        self.remote_ack_number = 0
        self.timeout_duration = 1.1 * self.constants.RTT

        self.connection_thread = None
        # На практике порты с меньшими номерами назначаются серверам
        # Поэтому, если порт локального сокета меньше, чем удалённого, то это сервер
        if self.udp_socket.getsockname()[1] < self.remote_addr[1]:
            self.connection_thread = threading.Thread(target=self.establish_server)
        else:
            self.connection_thread = threading.Thread(target=self.establish_client)
        self.connection_thread.start()

        self.send_queue = deque()
        self.received_data = bytes()

        self.data_sending_thread = threading.Thread(target=self.sending)
        self.data_receiving_thread = threading.Thread(target=self.receiving)
        self.stop_receiving = False

        self.data_received_event = threading.Event()
        self.ack_received_event = threading.Event()

        self.termination_thread = None

    def send(self, data: bytes):
        """
        Добавляет данные в очередь отправки и запускает поток отправки, если он не запущен.
        
        Поток отправки (data_sending_thread) необходим для:
        - Асинхронной отправки данных, чтобы не блокировать основной поток
        - Реализации надежной передачи через повторные отправки при потере пакетов
        - Контроля скорости отправки через механизм скользящего окна
        - Обработки подтверждений (ACK) от получателя
        
        Параметры:
        - data: данные для отправки
        """
        self.send_queue.appendleft(data)

        if not self.data_sending_thread.is_alive():
            self.data_sending_thread = threading.Thread(target=self.sending)
            self.data_sending_thread.start()

        return len(data)

    def sending(self):
        """
        Метод sending() реализует надежную передачу данных с использованием протокола TCP. 
        Надежность обеспечивается механизмом скользящего окна, который позволяет отправлять 
        несколько сегментов данных без ожидания подтверждения для каждого. Размер окна 
        определяется пропускной способностью канала и временем RTT, что позволяет 
        эффективно использовать доступную полосу пропускания. При обнаружении потери 
        сегмента (отсутствие ACK в течение таймаута) происходит повторная передача с 
        последнего подтвержденного номера последовательности. Контроль потока данных 
        осуществляется через отслеживание удаленного окна приема (window_size) и 
        локального номера последовательности, что предотвращает перегрузку получателя. 
        Метод также обеспечивает упорядоченную доставку данных благодаря использованию 
        порядковых номеров и механизма кумулятивных подтверждений.
        """
        if self.connection_thread.is_alive():
            self.connection_thread.join()

        while len(self.send_queue):
            start_seq = self.sequence_number
            data = self.send_queue.pop()
            while self.remote_ack_number < start_seq + len(data):
                # Проверка, позволяет ли окно отправлять больше данных
                if self.sequence_number < start_seq + len(data) and self.sequence_number < self.remote_ack_number + self.window_size:
                    send_bytes = min(
                        self.constants.MSS,
                        self.remote_ack_number + self.window_size - self.sequence_number,
                        start_seq + len(data) - self.sequence_number
                    )
                    self.sequence_number += send_bytes
                    self.send_data(
                        data[self.sequence_number - start_seq - send_bytes:self.sequence_number - start_seq]
                    )
                else:
                    self.ack_received_event.clear()
                    # Ожидание подтверждения или таймаута
                    if not self.ack_received_event.wait(self.constants.RST_TIMEOUT):
                        return
                    self.sequence_number = self.remote_ack_number

    def recv(self, n: int):
        """
        Метод recv() реализует надежный прием данных с использованием протокола TCP.
        Надежность обеспечивается механизмом кумулятивных подтверждений (cumulative ACK),
        при котором получатель отправляет номер последовательности следующего ожидаемого байта.
        Это позволяет отправителю определить, какие данные были успешно получены.
        
        Метод использует скользящее окно приема для управления потоком данных,
        буферизируя принятые сегменты и отправляя подтверждения только для
        непрерывной последовательности данных. При получении сегмента вне очереди
        или дубликата повторно отправляется ACK для последнего корректно принятого байта,
        что инициирует повторную передачу потерянных данных (механизм fast retransmit).
        
        Параметры:
        - n: количество байт для получения
        
        Возвращает:
        - bytes: полученные данные длиной n байт
        """
        if self.connection_thread.is_alive():
            self.connection_thread.join()

        data = bytes()
        not_ack = 0
        
        while len(data) < n:
            if not self._wait_for_data():
                not_ack = self._send_single_ack(not_ack)
                continue

            expected_seq = self.ack_number + len(self.received_data) - self.constants.HEADER
            if expected_seq == self.remote_sequence_number:
                data += self.received_data[self.constants.HEADER:]
                not_ack += len(self.received_data) - self.constants.HEADER
                self.ack_number = self.remote_sequence_number
            elif expected_seq <= self.remote_sequence_number:
                not_ack = self._send_single_ack(not_ack)

            if not_ack >= self.window_size:
                not_ack = self._send_single_ack(not_ack)

        self._send_final_acks()
        return data

    def _wait_for_data(self):
        result = self.data_received_event.wait(self.timeout_duration)
        self.data_received_event.clear()
        return result

    def _send_single_ack(self, not_ack):
        self.send_flags(self.constants.ACK)
        return 0

    def _send_final_acks(self):
        for _ in range(3):
            self.send_flags(self.constants.ACK)

    def receiving(self):
        """
        Метод receiving() реализует фоновый поток приёма данных в TCP-подобном протоколе.
        Он обрабатывает входящие пакеты следующим образом:
        - ACK флаги обновляют номер подтверждения удалённого узла
        - Пакеты данных сохраняются для последующей обработки методом receive()
        - FIN флаги инициируют процесс завершения соединения
        """
        while not self.stop_receiving:
            recv = self.recvfrom(self.constants.MTU)
            flag = int.from_bytes(recv[8:10], 'big')
            if flag == self.constants.ACK:
                # Обновление номера подтверждения удалённого узла
                self.remote_ack_number = max(
                    self.remote_ack_number,
                    int.from_bytes(recv[4:8], 'big')
                )
                self.ack_received_event.set()
            elif flag == 0:
                # Получение пакета данных
                self.received_data = recv
                self.remote_sequence_number = int.from_bytes(recv[0:4], 'big')
                self.data_received_event.set()
            elif flag == self.constants.FIN:
                # Инициация процесса завершения соединения при получении FIN
                self.termination_thread = threading.Thread(target=self.terminate_server)
                self.termination_thread.start()
                break

    def establish_client(self):
        """
        Метод establish_client() реализует инициацию клиентского соединения в TCP-подобном 
        протоколе. Он включает следующие шаги:
        - Инициализация последовательности клиента
        - Ожидание SYN и ACK от сервера
        - Финализация клиентского соединения
        """
        self._init_client_sequence()
        
        thread = threading.Thread(target=self.recv_flags, args=(self.constants.SYN | self.constants.ACK,))
        thread.start()
        
        self._wait_for_syn_ack(thread)
        self._finalize_client_connection()

    def _init_client_sequence(self):
        self.sequence_number = random.randint(0, 2 ** 32 - 1)
        self.ack_number = 0

    def _wait_for_syn_ack(self, thread):
        while thread.is_alive():
            self.send_flags(self.constants.SYN)
            thread.join(self.timeout_duration)
        self.ack_number = self.remote_sequence_number

    def _finalize_client_connection(self):
        self.send_flags(self.constants.ACK)
        self.remote_ack_number = self.sequence_number
        self.remote_sequence_number = self.ack_number
        self.data_receiving_thread.start()

    def establish_server(self):
        """
        Метод establish_server() реализует инициацию серверного соединения в TCP-подобном 
        протоколе. Он включает следующие шаги:
        - Инициализация последовательности сервера
        - Ожидание SYN от клиента
        - Отправка SYN и ACK
        - Финализация серверного соединения
        """
        self._init_server_sequence()
        self._wait_for_syn()
        
        thread = threading.Thread(target=self.recv_flags, args=(self.constants.ACK,))
        thread.start()
        
        self._wait_for_ack(thread)
        self._finalize_server_connection()

    def _init_server_sequence(self):
        self.sequence_number = random.randint(0, 2 ** 32 - 1)

    def _wait_for_syn(self):
        self.recv_flags(self.constants.SYN)
        self.ack_number = self.remote_sequence_number

    def _wait_for_ack(self, thread):
        while thread.is_alive():
            self.send_flags(self.constants.SYN | self.constants.ACK)
            thread.join(self.timeout_duration)

    def _finalize_server_connection(self):
        self.remote_ack_number = self.sequence_number
        self.remote_sequence_number = self.ack_number
        self.data_receiving_thread.start()

    def terminate_client(self):
        """
        Метод terminate_client() реализует завершение клиентского соединения.
        Он включает следующие шаги:
        - Остановка потока приёма данных
        - Ожидание подтверждения FIN и ACK
        - Отправка финального ACK
        """
        self._stop_receiving_thread()
        self._wait_for_fin_ack()
        self._send_final_client_ack()

    def _stop_receiving_thread(self):
        self.stop_receiving = True
        while self.data_receiving_thread.is_alive():
            self.send_flags(self.constants.FIN)
            self.data_receiving_thread.join(self.timeout_duration)

    def _wait_for_fin_ack(self):
        thread = threading.Thread(target=self.recv_flags, args=(self.constants.FIN | self.constants.ACK,))
        thread.start()
        
        while thread.is_alive() or self.remote_sequence_number != self.ack_number + 1:
            self.send_flags(self.constants.FIN)
            thread.join(self.timeout_duration)
        self.ack_number = self.remote_sequence_number

    def _send_final_client_ack(self):
        self.sequence_number += 1
        for _ in range(3):
            self.send_flags(self.constants.ACK)
        sleep(self.timeout_duration)

    def terminate_server(self):
        if self.data_sending_thread.is_alive():
            self.data_sending_thread.join()

        self._send_server_fin_ack()

    def _send_server_fin_ack(self):
        self.sequence_number += 1
        thread = threading.Thread(target=self.recv_flags, args=(self.constants.ACK,))
        thread.start()
        
        while thread.is_alive() or self.remote_sequence_number != self.ack_number + 1:
            try:
                self.send_flags(self.constants.FIN | self.constants.ACK)
            except OSError:
                return
            thread.join(self.timeout_duration)

    def send_flags(self, flags):
        """
        Метод send_flags() отправляет управляющие флаги и параметры окна вместе с данными.
        Он используется для отправки управляющих сообщений, таких как SYN, ACK, FIN и т.д.
        """
        self.sendto(
            self.sequence_number.to_bytes(4, 'big') +
            self.ack_number.to_bytes(4, 'big') +
            flags.to_bytes(2, 'big') +
            self.window_size.to_bytes(2, 'big')
        )

    def send_data(self, data, flags=0):
        """
        Метод send_data() отправляет данные вместе с управляющими флагами и параметрами окна.
        Он используется для отправки полезных данных, таких как текст, изображения, видео и т.д.
        """
        self.sendto(
            self.sequence_number.to_bytes(4, 'big') +
            self.ack_number.to_bytes(4, 'big') +
            flags.to_bytes(2, 'big') +
            self.window_size.to_bytes(2, 'big') +
            data
        )

    def recv_flags(self, flags):
        """
        Метод recv_flags() принимает управляющие флаги и параметры окна.
        Он используется для обработки управляющих сообщений, таких как SYN, ACK, FIN и т.д.
        """
        try:
            self.received_data = self.recvfrom(self.constants.HEADER)
            while int.from_bytes(self.received_data[8:10], 'big') != flags:
                self.received_data = self.recvfrom(self.constants.HEADER)
            self.remote_ack_number = int.from_bytes(self.received_data[4:8], 'big')
            self.remote_sequence_number = int.from_bytes(self.received_data[0:4], 'big')
        except OSError:
            return

    def close(self):
        """
        Метод close() завершает работу протокола.
        Он инициирует процесс завершения соединения и ожидает его завершения.
        """
        self._init_termination()
        self._wait_for_termination()
        super().close()

    def _init_termination(self):
        if not self.termination_thread:
            if self.data_sending_thread.is_alive():
                self.data_sending_thread.join()
            self.termination_thread = threading.Thread(target=self.terminate_client)
            self.termination_thread.start()

    def _wait_for_termination(self):
        if self.termination_thread.is_alive():
            self.termination_thread.join(self.constants.RST_TIMEOUT)