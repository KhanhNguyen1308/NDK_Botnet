# -*- coding: utf-8 -*-
# Import các thư viện cần thiết
import sys
import os
import time
import threading
import logging
import socket
import pythoncom
import requests # Gửi request HTTP
import wmi # Theo dõi sự kiện USB qua WMI
import psutil # Kiểm tra kết nối mạng
from PIL import Image, ImageDraw # Xử lý ảnh cho icon tray
from pystray import MenuItem as item, Icon as icon # Tạo icon tray

# --- Cấu hình ---
# URL của Django server cục bộ (thay đổi nếu cần)
# Ví dụ: 'http://127.0.0.1:8000/api/usb_event/'
DJANGO_SERVER_URL = 'http://localhost:8000/api/usb_event/'
# Tên file icon cho system tray (đặt cùng thư mục với script hoặc cung cấp đường dẫn đầy đủ)
ICON_FILENAME = 'icon.png'
# Tên file icon cho file .exe (dùng khi đóng gói)
APP_ICON_ICO = 'icon.ico'
# Khoảng thời gian (giây) giữa các lần kiểm tra sự kiện USB WMI
WMI_POLLING_INTERVAL = 2
# Timeout (giây) khi gửi request đến server Django
REQUEST_TIMEOUT = 10
# Địa chỉ IP và cổng để kiểm tra kết nối internet "toàn cầu"
# Sử dụng DNS của Google làm ví dụ
GLOBAL_NETWORK_CHECK_HOST = "8.8.8.8"
GLOBAL_NETWORK_CHECK_PORT = 53
GLOBAL_NETWORK_CHECK_TIMEOUT = 3

# --- Thiết lập Logging ---
# logging.basicConfig(level=logging.INFO,
#                     format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
#                     handlers=[logging.FileHandler("usb_monitor.log"), # Ghi log ra file
#                               logging.StreamHandler()]) # In log ra console (hữu ích khi debug)

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

# Lấy logger gốc (root logger)
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO) # Đặt level cơ bản cho logger gốc


# --- Biến toàn cục ---
# Cờ để dừng các luồng khi thoát ứng dụng
stop_event = threading.Event()
# Đối tượng icon tray
tray_icon = None
# Kết nối WMI (khởi tạo một lần để tối ưu)
wmi_connection = None

# --- Hàm tiện ích ---

def resource_path(relative_path):
    """ Lấy đường dẫn tuyệt đối đến tài nguyên, hoạt động cho cả dev và PyInstaller """
    try:
        # PyInstaller tạo thư mục tạm _MEIPASS và lưu tài nguyên ở đó
        base_path = sys._MEIPASS
    except Exception:
        # Nếu không chạy từ PyInstaller, dùng đường dẫn của script
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def create_default_icon(filename):
    """ Tạo file icon mặc định nếu không tìm thấy """
    try:
        image = Image.new('RGB', (64, 64), color = 'blue')
        d = ImageDraw.Draw(image)
        d.text((10,10), "USB", fill='white')
        filepath = resource_path(filename)
        image.save(filepath)
        logging.info(f"Đã tạo icon mặc định tại: {filepath}")
        return filepath
    except Exception as e:
        logging.error(f"Không thể tạo icon mặc định '{filename}': {e}")
        return None

def is_internet_connected():
    """
    Kiểm tra xem có kết nối đến mạng "toàn cầu" (internet) hay không.
    Cách đơn giản là thử kết nối đến một máy chủ đáng tin cậy bên ngoài.
    """
    try:
        # Tạo một socket và thử kết nối đến Google DNS server
        socket.setdefaulttimeout(GLOBAL_NETWORK_CHECK_TIMEOUT)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((GLOBAL_NETWORK_CHECK_HOST, GLOBAL_NETWORK_CHECK_PORT))
        logging.debug("Kiểm tra kết nối internet: Có kết nối internet.")
        return True
    except socket.error as ex:
        logging.debug(f"Kiểm tra kết nối internet: Không có kết nối internet ({ex}).")
        return False
    except Exception as e:
        logging.error(f"Lỗi không xác định khi kiểm tra kết nối internet: {e}")
        return False # Mặc định là không có kết nối nếu có lỗi lạ

def is_connected_to_local_network_only():
    """
    Kiểm tra xem máy tính CHỈ kết nối vào mạng cục bộ hay không
    (tức là có IP mạng LAN nhưng không ra được internet).
    Hàm này phức tạp hơn và cần định nghĩa rõ "mạng cục bộ" là gì.
    Cách đơn giản hóa: Nếu is_internet_connected() trả về False, ta giả định là chỉ có mạng nội bộ (nếu có).
    """
    # Hiện tại, logic này trùng với việc không có internet.
    # Nếu cần logic phức tạp hơn (vd: kiểm tra IP có nằm trong dải private không),
    # bạn cần sửa đổi hàm này dùng psutil để lấy địa chỉ IP của các card mạng.
    return not is_internet_connected()

def send_data_to_django(event_type, device_info):
    """
    Gửi thông tin sự kiện USB đến server Django.
    Chỉ gửi khi KHÔNG có kết nối internet (theo yêu cầu 3).
    """
    if not is_internet_connected():
        logging.info("Không có kết nối internet. Đang thử gửi dữ liệu đến server cục bộ.")
        payload = {
            'event_type': event_type, # 'connect' or 'disconnect'
            'device_info': device_info # Dictionary chứa thông tin thiết bị
        }
        try:
            response = requests.post(DJANGO_SERVER_URL, json=payload, timeout=REQUEST_TIMEOUT)
            response.raise_for_status() # Ném lỗi nếu HTTP status code là 4xx hoặc 5xx
            logging.info(f"Gửi dữ liệu thành công đến {DJANGO_SERVER_URL}. Status: {response.status_code}")
        except requests.exceptions.ConnectionError:
            logging.error(f"Không thể kết nối đến server Django tại {DJANGO_SERVER_URL}. Server có đang chạy không?")
        except requests.exceptions.Timeout:
            logging.warning(f"Hết thời gian chờ khi gửi dữ liệu đến {DJANGO_SERVER_URL}.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Lỗi khi gửi dữ liệu đến Django server: {e}")
        except Exception as e:
            logging.error(f"Lỗi không xác định khi gửi dữ liệu: {e}")
    else:
        logging.info("Đã phát hiện kết nối internet. Bỏ qua việc gửi dữ liệu đến server cục bộ.")

# --- Luồng theo dõi USB ---
def monitor_usb_devices(stop_event_flag):
    """
    Luồng này sử dụng WMI để theo dõi sự kiện cắm/rút thiết bị USB.
    """
    global wmi_connection
    logging.info("Bắt đầu luồng theo dõi USB...")
    pythoncom.CoInitialize()
    try:
        # Khởi tạo kết nối WMI nếu chưa có
        if wmi_connection is None:
            wmi_connection = wmi.WMI()
            logging.info("Đã kết nối WMI.")
    except wmi.x_wmi as e:
        print(e)
        logging.critical(f"Lỗi nghiêm trọng khi khởi tạo WMI: {e}. Có thể cần quyền Admin hoặc dịch vụ WMI đang gặp sự cố.")
        # Có thể thêm hành động ở đây, ví dụ: thông báo cho người dùng và thoát
        # Hoặc cố gắng kết nối lại sau một khoảng thời gian
        return # Thoát luồng nếu không kết nối được WMI

    # Tạo các watcher WMI cho sự kiện cắm và rút USB
    # Sử dụng Win32_PnPEntity vì nó chứa nhiều thông tin hơn Win32_USBHub
    # Lọc các thiết bị có 'USB' trong mô tả hoặc ID để giảm nhiễu
    # __InstanceCreationEvent: Thiết bị được thêm vào hệ thống
    # __InstanceDeletionEvent: Thiết bị bị gỡ bỏ khỏi hệ thống
    try:
        usb_connect_watcher = wmi_connection.watch_for(
            notification_type="Creation",
            wmi_class="Win32_PnPEntity",
            delay_secs=WMI_POLLING_INTERVAL,
            # Điều kiện lọc để chỉ lấy thiết bị có vẻ là USB
            # Bạn có thể cần điều chỉnh điều kiện này tùy thuộc vào loại thiết bị cần theo dõi
            # WHERE TargetInstance.Description LIKE '%USB%' OR TargetInstance.DeviceID LIKE 'USB\\%'
        )
        usb_disconnect_watcher = wmi_connection.watch_for(
            notification_type="Deletion",
            wmi_class="Win32_PnPEntity",
            delay_secs=WMI_POLLING_INTERVAL,
            # WHERE TargetInstance.Description LIKE '%USB%' OR TargetInstance.DeviceID LIKE 'USB\\%'
        )
        logging.info("Đã tạo WMI watchers thành công.")

        # Vòng lặp chính để chờ sự kiện, kết thúc khi stop_event được set
        while not stop_event_flag.is_set():
            try:
                # Kiểm tra sự kiện kết nối (timeout nhỏ để vòng lặp không bị block quá lâu)
                event_connect = usb_connect_watcher(timeout_ms=500)
                if event_connect and ( 'USB' in (event_connect.Description or '') or 'USB\\' in (event_connect.DeviceID or '')):
                    device_info = {
                        'Caption': getattr(event_connect, 'Caption', 'N/A'),
                        'Description': getattr(event_connect, 'Description', 'N/A'),
                        'DeviceID': getattr(event_connect, 'DeviceID', 'N/A'),
                        'Manufacturer': getattr(event_connect, 'Manufacturer', 'N/A'),
                        'PNPDeviceID': getattr(event_connect, 'PNPDeviceID', 'N/A'),
                        'Status': getattr(event_connect, 'Status', 'N/A'),
                    }
                    logging.info(f"Phát hiện kết nối USB: {device_info.get('Description') or device_info.get('DeviceID')}")
                    # Gửi dữ liệu trong một luồng riêng để không chặn việc theo dõi
                    threading.Thread(target=send_data_to_django, args=('connect', device_info), daemon=True).start()

                # Kiểm tra sự kiện ngắt kết nối
                event_disconnect = usb_disconnect_watcher(timeout_ms=500)
                if event_disconnect and ('USB' in (event_disconnect.Description or '') or 'USB\\' in (event_disconnect.DeviceID or '')):
                    device_info = {
                        'Caption': getattr(event_disconnect, 'Caption', 'N/A'),
                        'Description': getattr(event_disconnect, 'Description', 'N/A'),
                        'DeviceID': getattr(event_disconnect, 'DeviceID', 'N/A'),
                        'Manufacturer': getattr(event_disconnect, 'Manufacturer', 'N/A'),
                        'PNPDeviceID': getattr(event_disconnect, 'PNPDeviceID', 'N/A'),
                        # Trạng thái có thể không còn hữu ích khi thiết bị đã rút
                    }
                    logging.info(f"Phát hiện ngắt kết nối USB: {device_info.get('Description') or device_info.get('DeviceID')}")
                    # Gửi dữ liệu trong một luồng riêng
                    threading.Thread(target=send_data_to_django, args=('disconnect', device_info), daemon=True).start()

            except wmi.x_wmi_timed_out:
                # Bỏ qua lỗi timeout, đây là điều bình thường khi không có sự kiện
                continue
            except Exception as e:
                # Ghi lại các lỗi WMI khác có thể xảy ra trong vòng lặp
                logging.error(f"Lỗi trong vòng lặp WMI watcher: {e}")
                # Chờ một chút trước khi thử lại để tránh vòng lặp lỗi liên tục
                time.sleep(5)

            # Chờ một chút giữa các lần kiểm tra để giảm tải CPU, ngay cả khi watcher có timeout
            # time.sleep(0.1) # Có thể bỏ nếu watcher timeout đủ nhỏ

    except Exception as e:
        logging.critical(f"Lỗi nghiêm trọng trong luồng theo dõi USB: {e}. Luồng sẽ dừng.")
        # Có thể cần thông báo cho người dùng ở đây
    finally:
        logging.info("Đang dừng luồng theo dõi USB...")
        pythoncom.CoUninitialize() # Uninitialize COM khi luồng kết thúc
        # Dọn dẹp (nếu cần thiết, mặc dù watcher thường tự dọn khi thoát)
        # Ví dụ: del usb_connect_watcher, del usb_disconnect_watcher


# --- Thiết lập và chạy Icon Tray ---
def setup_tray_icon(stop_event_flag):
    # Thiết lập và chạy icon trên khay hệ thống.
    global tray_icon
    icon_path = resource_path(ICON_FILENAME)
    # Kiểm tra xem file icon có tồn tại không, nếu không thì tạo icon mặc định
    if not os.path.exists(icon_path):
        logging.warning(f"Không tìm thấy file icon '{ICON_FILENAME}'. Đang thử tạo icon mặc định.")
        icon_path = create_default_icon(ICON_FILENAME)
        if not icon_path:
            logging.error("Không thể tạo hoặc tìm thấy icon. Icon tray sẽ không hoạt động.")
            # Có thể quyết định dừng ứng dụng ở đây nếu icon là bắt buộc
            stop_event_flag.set() # Báo hiệu các luồng khác dừng lại
            return

    try:
        image = Image.open(icon_path)
    except Exception as e:
        logging.error(f"Không thể mở file icon '{icon_path}': {e}. Icon tray sẽ không hoạt động.")
        stop_event_flag.set()
        return

    # Định nghĩa hành động khi nhấn vào các mục menu
    def exit_action(icon_obj, item_obj):
        logging.info("Người dùng yêu cầu thoát từ menu tray.")
        stop_event_flag.set() # Gửi tín hiệu dừng cho các luồng khác
        if tray_icon:
             tray_icon.stop() # Dừng vòng lặp của icon tray

    # Tạo menu cho icon tray
    menu = (item('Trạng thái: Đang chạy', None, enabled=False), # Mục menu chỉ hiển thị thông tin
            item('Thoát', exit_action))

    # Tạo đối tượng icon
    tray_icon = icon("USBMonitor", image, "USB Monitor đang chạy", menu)

    # Chạy icon tray (hàm này sẽ block luồng chính cho đến khi icon.stop() được gọi)
    logging.info("Hiển thị icon trên khay hệ thống.")
    try:
        tray_icon.run()
    except Exception as e:
        logging.error(f"Lỗi khi chạy icon tray: {e}")
        stop_event_flag.set() # Đảm bảo các luồng khác cũng dừng nếu tray bị lỗi

    logging.info("Đã đóng icon tray.")


# --- Hàm chính ---
if __name__ == "__main__":
    logging.info("Bắt đầu ứng dụng USB Monitor...")

    # Kiểm tra xem một instance khác có đang chạy không (cách đơn giản)
    # Bạn có thể dùng thư viện như `portalocker` hoặc `win32event` để tạo mutex nếu cần cơ chế khóa chặt chẽ hơn
    try:
        # Thử tạo một socket server trên một cổng cố định. Nếu thành công, không có instance nào khác.
        # Nếu lỗi AddrInUse, có thể đã có instance khác chạy.
        lock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lock_socket.bind(("127.0.0.1", 59876)) # Chọn một cổng không dùng
        logging.info("Khóa instance thành công.")
    except socket.error as e:
        if e.errno == socket.errno.WSAEADDRINUSE: # Address already in use
             logging.warning("Một instance khác của ứng dụng có vẻ đang chạy. Đang thoát...")
             # Có thể hiển thị thông báo cho người dùng ở đây
             sys.exit(1) # Thoát chương trình
        else:
             logging.error(f"Lỗi không xác định khi kiểm tra instance: {e}")
             # Có thể tiếp tục chạy hoặc thoát tùy theo mức độ nghiêm trọng
             # sys.exit(1)

    # Tạo và khởi động luồng theo dõi USB
    # daemon=True nghĩa là luồng này sẽ tự động kết thúc khi luồng chính (tray icon) kết thúc
    usb_thread = threading.Thread(target=monitor_usb_devices, args=(stop_event,), name="USBMonitorThread", daemon=True)
    usb_thread.start()

    # Thiết lập và chạy icon tray (đây sẽ là luồng chính)
    # Hàm này sẽ block cho đến khi người dùng chọn Thoát
    setup_tray_icon(stop_event)

    # Dọn dẹp sau khi icon tray đã đóng
    logging.info("Đang chờ luồng USB kết thúc...")
    # Không cần join() nếu luồng là daemon, nhưng chờ một chút để log được ghi
    time.sleep(1)

    # Đóng socket khóa
    if 'lock_socket' in locals() and lock_socket:
        lock_socket.close()
        logging.info("Đã giải phóng khóa instance.")

    logging.info("Ứng dụng USB Monitor đã kết thúc.")
    sys.exit(0) # Thoát hoàn toàn