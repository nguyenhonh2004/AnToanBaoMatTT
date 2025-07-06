from flask import Flask, render_template, request, jsonify, send_file
import socket
import json
import base64
import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import threading
import tempfile

app = Flask(__name__)

class SenderWeb:
    def __init__(self):
        self.selected_file = None
        self.socket_connection = None
        self.is_connected = False
        self.logs = []
        self.receiver_ip = "localhost"  # Mặc định là localhost
        self.receiver_port = 12345
        self.receiver_ready = False
        
    def log(self, msg):
        self.logs.append(f"{time.strftime('%H:%M:%S')} - {msg}")
        if len(self.logs) > 100:  # Giới hạn log
            self.logs.pop(0)
            
    def get_logs(self):
        return self.logs.copy()

    def get_local_ip(self):
        """Lấy địa chỉ IP local của máy"""
        try:
            # Tạo socket tạm thời để lấy IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

sender = SenderWeb()

@app.route('/')
def index():
    return render_template('sender.html')

@app.route('/get_local_ip')
def get_local_ip():
    """API để lấy địa chỉ IP local"""
    return jsonify({
        'local_ip': sender.get_local_ip()
    })

@app.route('/set_receiver_ip', methods=['POST'])
def set_receiver_ip():
    """API để thiết lập địa chỉ IP của receiver"""
    data = request.get_json()
    if data and 'ip' in data:
        sender.receiver_ip = data['ip']
        sender.log(f"🎯 Đã thiết lập địa chỉ receiver: {sender.receiver_ip}")
        return jsonify({
            'success': True,
            'message': f'Đã thiết lập địa chỉ receiver: {sender.receiver_ip}',
            'logs': sender.get_logs()
        })
    return jsonify({'error': 'Thiếu địa chỉ IP'})

@app.route('/select_file', methods=['POST'])
def select_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Không có file được chọn'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Không có file được chọn'})
    
    # Lưu file tạm thời
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, file.filename)
    file.save(temp_path)
    
    sender.selected_file = temp_path
    sender.log(f"📁 Đã chọn file: {file.filename}")
    
    return jsonify({
        'success': True,
        'filename': file.filename,
        'logs': sender.get_logs()
    })

@app.route('/connect', methods=['POST'])
def connect():
    try:
        sender.socket_connection = socket.socket()
        sender.log(f"🔄 Đang kết nối đến {sender.receiver_ip}:{sender.receiver_port}...")
        sender.socket_connection.connect((sender.receiver_ip, sender.receiver_port))
        sender.is_connected = True
        return jsonify({
            'success': True,
            'status': 'Đã kết nối',
            'logs': sender.get_logs()
        })
    except Exception as e:
        sender.log(f"❌ Lỗi kết nối đến {sender.receiver_ip}: {str(e)}")
        if sender.socket_connection:
            sender.socket_connection.close()
            sender.socket_connection = None
        sender.is_connected = False
        return jsonify({
            'success': False,
            'error': str(e),
            'status': 'Kết nối thất bại',
            'logs': sender.get_logs()
        })

@app.route('/send_hello', methods=['POST'])
def send_hello():
    try:
        if not sender.is_connected or not sender.socket_connection:
            return jsonify({'success': False, 'error': 'Chưa kết nối tới receiver', 'logs': sender.get_logs()})
        sender.socket_connection.sendall(b"Hello!")
        sender.log("📤 Đã gửi tín hiệu Hello! đến receiver")
        response = sender.socket_connection.recv(1024)
        if response == b"Ready!":
            sender.receiver_ready = True
            sender.log("✅ Người nhận đã sẵn sàng nhận file!")
            return jsonify({'success': True, 'logs': sender.get_logs()})
        else:
            raise Exception("Người nhận không sẵn sàng")
    except Exception as e:
        sender.log(f"❌ Lỗi khi gửi Hello: {str(e)}")
        sender.receiver_ready = False
        return jsonify({'success': False, 'error': str(e), 'logs': sender.get_logs()})

@app.route('/send_file', methods=['POST'])
def send_file():
    if not sender.selected_file:
        return jsonify({'error': 'Vui lòng chọn file trước khi gửi!'})
    
    if not sender.is_connected:
        return jsonify({'error': 'Vui lòng kết nối trước khi gửi!'})
    
    if not sender.receiver_ready:
        return jsonify({'error': 'Người nhận chưa sẵn sàng nhận file! Hãy gửi Hello trước.'})
    
    try:
        # Load khóa
        with open("sender_private.pem", "rb") as f:
            sender_private_key = RSA.import_key(f.read())
        with open("receiver_public.pem", "rb") as f:
            receiver_public_key = RSA.import_key(f.read())

        filename = os.path.basename(sender.selected_file)
        # Lấy thông tin file
        file_size = os.path.getsize(sender.selected_file)
        metadata = {
            "filename": filename,
            "timestamp": time.ctime(),
            "filesize": file_size
        }
        h = SHA512.new(json.dumps(metadata).encode())
        signature = pkcs1_15.new(sender_private_key).sign(h)
        meta_packet = {
            "metadata": metadata,
            "signature": base64.b64encode(signature).decode()
        }
        sender.socket_connection.sendall(json.dumps(meta_packet).encode())

        session_key = DES3.adjust_key_parity(get_random_bytes(24))
        cipher_rsa = PKCS1_OAEP.new(receiver_public_key, hashAlgo=SHA512)
        enc_session_key = cipher_rsa.encrypt(session_key)
        sender.socket_connection.sendall(base64.b64encode(enc_session_key))

        with open(sender.selected_file, "rb") as f:
            data = f.read()
        chunk_size = len(data) // 3
        chunks = [data[i * chunk_size : (i + 1) * chunk_size] for i in range(2)]
        chunks.append(data[2 * chunk_size:])

        for idx, chunk in enumerate(chunks):
            iv = get_random_bytes(8)
            cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(chunk, DES3.block_size))

            h = SHA512.new(iv + ciphertext)
            sig = pkcs1_15.new(sender_private_key).sign(h)

            packet = {
                "index": idx,
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "hash": h.hexdigest(),
                "sig": base64.b64encode(sig).decode()
            }

            sender.socket_connection.sendall((json.dumps(packet) + "\n").encode())
            sender.log(f"📤 Đã gửi đoạn {idx}")

            # Gửi chữ ký xác nhận bằng khóa riêng tư (sau khi gửi xong đoạn)
            h_ack = SHA512.new(iv + ciphertext)
            sig_ack = pkcs1_15.new(sender_private_key).sign(h_ack)
            sender.socket_connection.sendall(base64.b64encode(sig_ack) + b"\n")
            sender.log(f"🔏 Đã gửi chữ ký xác nhận cho đoạn {idx}")

        ack = sender.socket_connection.recv(1024)
        if ack == b"ACK":
            sender.log("🎉 Gửi file thành công!")
            # Đóng kết nối sau khi gửi xong
            sender.socket_connection.close()
            sender.socket_connection = None
            sender.is_connected = False
            return jsonify({
                'success': True,
                'message': 'File đã được gửi thành công!',
                'logs': sender.get_logs()
            })
        else:
            sender.log("❌ Gửi file thất bại.")
            return jsonify({
                'success': False,
                'error': 'Gửi file thất bại!',
                'logs': sender.get_logs()
            })
            
    except Exception as e:
        sender.log(f"❌ Lỗi: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Không thể gửi file: {str(e)}',
            'logs': sender.get_logs()
        })

@app.route('/get_status')
def get_status():
    return jsonify({
        'is_connected': sender.is_connected,
        'selected_file': os.path.basename(sender.selected_file) if sender.selected_file else None,
        'receiver_ip': sender.receiver_ip,
        'local_ip': sender.get_local_ip(),
        'receiver_ready': sender.receiver_ready,
        'logs': sender.get_logs()
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0') 