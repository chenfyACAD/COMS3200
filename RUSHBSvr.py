import socket
import time

MAX_PACKET_SIZE = 1500
MAX_PAYLOAD_SIZE = 1464

# follow the flag header structure
FLAGS = {"GET": "0010000", "DAT": "0001000", "FIN": "0000100", "DAT_ACK": "1001000",
         "FIN_ACK": "1000100", "DAT_NAK": "0101000", "GET_CHK": "0010010",
         "DAT_CHK": "0001010", "FIN_CHK": "0000110", "DAT_ACK_CHK": "1001010",
         "FIN_ACK_CHK": "1000110", "DAT_NAK_CHK": "0101010"}


class Server:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", 0))
        # store all unfinished sessions
        self.sessions = []

    def run(self):
        print(self.server.getsockname()[1])
        while True:
            for session in self.sessions:
                if time.time() - session.time > 4:
                    self.resend_packet(session)
            self.server.settimeout(1)

            try:
                package, port = self.server.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                self.server.settimeout(None)
                continue

            sequence_num = int.from_bytes(package[:2], byteorder='big')
            ack_num = int.from_bytes(package[2:4], byteorder='big')
            checksum = int.from_bytes(package[4:6], byteorder='big')
            flag = bin(int.from_bytes(package[6:8], byteorder='big'))[2:].zfill(16)[:7]
            payload = package[8:].rstrip(b'\x00')

            current_session = None
            for session in self.sessions:
                if session.port == port:
                    current_session = session

            # start a new session
            if current_session is None:
                if sequence_num == 1 and ack_num == 0:
                    if flag == FLAGS["GET"] and checksum != 0:
                        continue
                    if flag == FLAGS["GET_CHK"] and checksum != compute_checksum(package[8:]):
                        continue
                    try:
                        self.start_new_session(port, flag, payload)
                    except IOError:
                        continue
                else:
                    continue

            if sequence_num == current_session.sequence_num + 1 \
                    and ack_num == current_session.server_sequence_num \
                    and flag in current_session.required_flag:

                if flag == FLAGS["DAT_ACK"]:
                    if len(current_session.required_file) <= MAX_PAYLOAD_SIZE:
                        current_session.required_file = None
                        current_session.payload = None
                        current_session.sequence_num = sequence_num
                        current_session.server_sequence_num += 1
                        current_session.required_flag = [FLAGS["FIN_ACK"]]
                        self.send_packet(current_session, 0, FLAGS["FIN"])
                    else:
                        current_session.required_file = current_session.required_file[MAX_PAYLOAD_SIZE:]
                        current_session.payload = current_session.required_file[:MAX_PAYLOAD_SIZE]
                        current_session.sequence_num = sequence_num
                        current_session.server_sequence_num += 1
                        self.send_packet(current_session, 0, FLAGS["DAT"])
                elif flag == FLAGS["DAT_NAK"]:
                    current_session.sequence_num = sequence_num
                    self.resend_packet(current_session)
                elif flag == FLAGS["FIN_ACK"]:
                    current_session.sequence_num = sequence_num
                    current_session.server_sequence_num += 1
                    self.send_packet(current_session, current_session.sequence_num, FLAGS["FIN_ACK"])
                    self.sessions.remove(current_session)
                elif flag == FLAGS["DAT_ACK_CHK"]:
                    if checksum == compute_checksum(payload):
                        if len(current_session.required_file) <= MAX_PAYLOAD_SIZE:
                            current_session.required_file = None
                            current_session.payload = None
                            current_session.server_sequence_num += 1
                            current_session.sequence_num = sequence_num
                            current_session.required_flag = [FLAGS["FIN_ACK_CHK"]]
                            self.send_checksum_packet(current_session, 0, FLAGS["FIN_CHK"])
                        else:
                            current_session.required_file = current_session.required_file[MAX_PAYLOAD_SIZE:]
                            current_session.payload = current_session.required_file[:MAX_PAYLOAD_SIZE]
                            current_session.sequence_num = sequence_num
                            current_session.server_sequence_num += 1
                            self.send_checksum_packet(current_session, 0, FLAGS["DAT_CHK"])
                elif flag == FLAGS["FIN_ACK_CHK"]:
                    if checksum == compute_checksum(payload):
                        current_session.sequence_num = sequence_num
                        current_session.server_sequence_num += 1
                        self.send_checksum_packet(current_session, current_session.sequence_num, FLAGS["FIN_ACK_CHK"])
                        self.sessions.remove(current_session)
                elif flag == FLAGS["DAT_NAK_CHK"]:
                    if checksum == compute_checksum(payload):
                        current_session.sequence_num = sequence_num
                        self.resend_packet(current_session)
            else:
                continue

    def start_new_session(self, port, flag, payload):
        if flag == FLAGS["GET"]:
            file = load_file(payload)
            current_session = Session(port, 1, 1, file, [FLAGS["DAT_ACK"], FLAGS["DAT_NAK"]], False)
            self.sessions.append(current_session)
            self.send_packet(current_session, 0, FLAGS["DAT"])
        elif flag == FLAGS["GET_CHK"]:
            file = load_file(payload)
            current_session = Session(port, 1, 1, file, [FLAGS["DAT_ACK_CHK"], FLAGS["DAT_NAK_CHK"]], True)
            self.sessions.append(current_session)
            self.send_checksum_packet(current_session, 0, FLAGS["DAT_CHK"])

    def send_packet(self, session, ack_num, flag):
        packet = build_package(session.server_sequence_num, ack_num, 0, flag, session.payload)
        self.server.sendto(packet, session.port)
        session.time = time.time()
        return

    def send_checksum_packet(self, session, ack_num, flag):
        if session.payload is None:
            checksum = compute_checksum((0).to_bytes(MAX_PAYLOAD_SIZE, byteorder='big'))
        else:
            checksum = compute_checksum(session.payload.encode('utf-8'))
        packet = build_package(session.server_sequence_num, ack_num, checksum, flag, session.payload)
        self.server.sendto(packet, session.port)
        session.time = time.time()
        return

    def resend_packet(self, session):
        if session.checksum:
            if session.payload is not None:
                self.send_checksum_packet(session, 0, FLAGS["DAT_CHK"])
            else:
                self.send_checksum_packet(session, 0, FLAGS["FIN_CHK"])
        else:
            if session.payload is not None:
                self.send_packet(session, 0, FLAGS["DAT"])
            else:
                self.send_packet(session, 0, FLAGS["FIN"])
        return


class Session:
    def __init__(self, port, sequence_num, server_sequence_num, required_file, required_flag, checksum):
        self.port = port
        self.sequence_num = sequence_num
        self.server_sequence_num = server_sequence_num
        self.required_file = required_file
        self.payload = self.required_file[:MAX_PAYLOAD_SIZE]
        self.required_flag = required_flag
        self.checksum = checksum
        self.time = 0


def load_file(payload):
    file_name = payload.decode()
    file = open(file_name, 'r')
    content = file.read()
    file.close()
    return content


def build_package(sequence_num, ack_num, checksum, flag, payload):
    header = bin(sequence_num)[2:].zfill(16)
    header += bin(ack_num)[2:].zfill(16)
    header += bin(checksum)[2:].zfill(16)
    header += flag.ljust(13, '0')
    # version code
    header += bin(0)[2:]
    header += bin(1)[2:]
    header += bin(0)[2:]
    if payload is None:
        data = (0).to_bytes(MAX_PAYLOAD_SIZE, byteorder='big')
    else:
        data = payload.encode("utf-8")
        data += bytes(MAX_PAYLOAD_SIZE - len(payload))
    header = bytes([int(header[i:i + 8], 2) for i in range(0, 64, 8)])
    return header + data


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):
        w = b_str[i] + (b_str[i + 1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff


def main():
    pass


if __name__ == '__main__':
    main()
