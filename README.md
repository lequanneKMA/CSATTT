# CSATTT
Đây là một ứng dụng mã hóa/giải mã file sử dụng thuật toán AES (Advanced Encryption Standard) với các chức năng chính:

Giao diện người dùng:

Cho phép chọn chế độ mã hóa hoặc giải mã

Chọn file đầu vào/đầu ra

Nhập khóa hoặc tự động tạo khóa ngẫu nhiên

Lựa chọn độ dài khóa (AES-128, AES-192, AES-256)

Chức năng mã hóa:

Mã hóa file sử dụng AES với chế độ CBC (Cipher Block Chaining)

Tự động thêm đệm PKCS#7

Tạo IV (Initialization Vector) ngẫu nhiên

Thêm header xác thực file

Chức năng giải mã:

Giải mã file đã được mã hóa

Kiểm tra tính hợp lệ của file và khóa

Tự động loại bỏ đệm PKCS#7

Bảo mật:

Kiểm tra checksum và magic number để xác thực file

Hỗ trợ 3 độ dài khóa (128-bit, 192-bit, 256-bit)

Sử dụng IV ngẫu nhiên cho mỗi lần mã hóa

Tiện ích:

Đo thời gian thực hiện mã hóa/giải mã

Tự động đề xuất tên file đầu ra

Thông báo trạng thái chi tiết
