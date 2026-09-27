# Security Requirements: json_search()

Được rút ra từ `threat-model.md`. Mỗi yêu cầu được viết sao cho có thể kiểm chứng
trực tiếp bằng một test trong `test_json_search.py`.

| ID | Yêu cầu | Threat liên quan | Mức ưu tiên | Được kiểm chứng bởi |
|----|---------|--------------------|----------|-------------|
| SR-1 | Hệ thống chỉ trả về giá trị của một trường cho các role nằm trong danh sách được phép truy cập trường đó (định nghĩa trong `policy.py`). | T4 (Information Disclosure), T6 (Elevation of Privilege) | Bắt buộc | `test_wrong_role_cannot_read_secret` |
| SR-2 | Giá trị `role` mà `json_search()` sử dụng phải đến từ session/token đã xác thực, không được nhận trực tiếp từ tham số client tự khai báo. | T1 (Spoofing) | Nên có | Review thủ công / integration test |
| SR-3 | Mọi lời gọi `json_search()` có chạm đến trường bị hạn chế phải được ghi log, gồm actor, role, key, kết quả, thời điểm. | T3 (Repudiation) | Nên có | Kiểm tra log |
| SR-4 | `json_search()` phải giới hạn độ sâu đệ quy hoặc kích thước input. | T5 (Denial of Service) | Có thể có | `test_large_input_rejected` (tùy chọn) |
| SR-5 | Mọi thay đổi đối với `policy.py` phải được review/approve trước khi merge. | T2 (Tampering) | Nên có | Quy trình review PR / branch protection |

## Ví dụ tham khảo (SR-1)

```python
def test_wrong_role_cannot_read_secret(self):
    """role viewer không được nhận giá trị của apiKey"""
    result = json_search("apiKey", data, role="viewer")
    self.assertEqual([], result)
```
