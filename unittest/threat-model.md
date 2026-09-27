# Threat Model: json_search()
## 1. Đang xây dựng cái gì?

`json_search()` tìm kiếm đệ quy trong JSON trả về từ một API giám sát hạ tầng mạng
(dữ liệu mẫu trong `test_data.py`) và trả về danh sách các cặp key/value khớp với
key được truyền vào. Hàm được gọi bởi ba loại người dùng: `admin`, `operator`,
`viewer`.

### Data flow

```
[Caller (admin/operator/viewer)]
        | key, input_object, role
        v
  [json_search()] ---- đọc dữ liệu ----> [test_data.py: dữ liệu giám sát mạng]
        |
        v
[Danh sách key/value khớp] ---> [Caller]
```

### Trust boundary

Có một trust boundary giữa **role của caller** và **dữ liệu trả về**: các role thấp
hơn `admin` không được nhận giá trị của trường chỉ dành cho admin. Ở phiên bản gốc,
boundary này chưa được thực thi — hàm hoàn toàn không biết đến khái niệm `role`.

## 2. Điều gì có thể sai? (STRIDE)

| # | Nhóm | Mô tả threat | Thành phần bị ảnh hưởng | Biện pháp giảm thiểu |
|---|------|--------------|--------------------------|------------------------|
| T1 | Spoofing (Giả mạo danh tính) | Caller tự khai báo giá trị `role` (ví dụ `role="admin"`) mà không qua xác thực, giả làm người dùng quyền cao hơn. | Tham số `role` | Chỉ lấy `role` từ session/token đã xác thực; không tin tưởng giá trị role do client tự truyền vào. |
| T2 | Tampering (Giả mạo dữ liệu) | `policy.py` (bảng phân quyền role/trường dữ liệu) bị chỉnh sửa mà không qua review để mở rộng quyền truy cập. | `policy.py` | Bắt buộc review/approve pull request cho mọi thay đổi `policy.py`. |
| T3 | Repudiation (Chối bỏ hành vi) | Người dùng truy vấn được dữ liệu nhạy cảm nhưng không có log, nên có thể sau này chối bỏ việc đã truy cập. | Lời gọi hàm (chưa có logging) | Ghi log mỗi lần gọi liên quan trường nhạy cảm: actor, role, key, kết quả, thời điểm. |
| T4 | **Information Disclosure (Rò rỉ thông tin)** | Hàm trả về nguyên giá trị của trường (ví dụ `apiKey`, định danh thiết bị) cho role không đủ quyền, do chưa kiểm tra role trước khi trả kết quả. | Giá trị trả về của `json_search()` | Lọc trường trả về theo quyền của role, dựa trên bảng phân quyền trong `policy.py`, trước khi trả kết quả. |
| T5 | Denial of Service | `input_object` lồng sâu hoặc có kích thước lớn gây đệ quy vô hạn (tràn stack / tốn CPU). | Logic tìm kiếm đệ quy | Giới hạn độ sâu đệ quy/kích thước input; thêm timeout ở tầng gọi API. |
| T6 | **Elevation of Privilege (Leo thang đặc quyền)** | Role thấp (`viewer`) nhận được dữ liệu chỉ dành cho `admin`, tương đương đạt được mức truy cập của admin mà không cần chiếm session admin. | Đường thực thi kiểm tra role | Thực thi kiểm tra role ngay trong `json_search()` (defense in depth), không chỉ dựa vào tầng gọi bên ngoài. |

*T4 và T6 là hai threat bắt buộc theo yêu cầu đề bài (Information Disclosure /
Elevation of Privilege).*

## 3. Asset có nguy cơ bị lộ

- Định danh thiết bị (hostname, IP, serial number, MAC address)
- Thông tin xác thực SNMP (community string / `apiKey`)
- Thông tin topology hạ tầng mạng (có thể dùng để trinh sát trước khi tấn công)

