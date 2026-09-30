# Security Requirements for `json_search()`

## 1. Mục đích

Hàm `json_search()` được sử dụng để tìm kiếm giá trị của một trường (`key`) trong dữ liệu JSON có cấu trúc lồng nhau.

Do dữ liệu có thể chứa các thông tin nhạy cảm như thông tin định danh thiết bị, địa chỉ quản trị và chuỗi xác thực SNMP, hàm `json_search()` phải kiểm soát quyền truy cập dựa trên `role` của người gọi trước khi trả về kết quả.

Các quyền truy cập được xác định trong `policy.py`:

```python
POLICY = {
    "apiKey": ["admin"],
    "managementIpAddress": ["admin", "operator"],
    "issueSummary": ["admin", "operator", "viewer"],
}
```

---

## 2. Security Requirements

### SR-01 - Role-Based Access Control

Hệ thống phải kiểm tra `role` của người gọi trước khi trả về giá trị của một `key`.

Một role chỉ được phép truy cập một `key` nếu role đó nằm trong danh sách được phép của `POLICY`.

Ví dụ:

```text
apiKey                  → admin
managementIpAddress     → admin, operator
issueSummary            → admin, operator, viewer
```

---

### SR-02 - API Key Protection

Chỉ role `admin` được phép truy cập trường `apiKey`.

Các role `operator` và `viewer` không được nhận giá trị của trường này.

Ví dụ:

```python
json_search("apiKey", data, role="admin")
```

được phép trả về kết quả.

Trong khi:

```python
json_search("apiKey", data, role="operator")
json_search("apiKey", data, role="viewer")
```

phải bị từ chối và trả về danh sách rỗng.

---

### SR-03 - Management IP Protection

Chỉ role `admin` và `operator` được phép truy cập trường `managementIpAddress`.

Role `viewer` không được phép nhận giá trị của trường này.

Ví dụ:

```python
json_search("managementIpAddress", data, role="admin")
json_search("managementIpAddress", data, role="operator")
```

được phép trả về kết quả.

Trong khi:

```python
json_search("managementIpAddress", data, role="viewer")
```

phải bị từ chối và trả về danh sách rỗng.

---

### SR-04 - Issue Summary Access

Các role `admin`, `operator` và `viewer` được phép truy cập trường `issueSummary`.

Ví dụ:

```python
json_search("issueSummary", data, role="admin")
json_search("issueSummary", data, role="operator")
json_search("issueSummary", data, role="viewer")
```

được phép trả về kết quả nếu trường `issueSummary` tồn tại trong dữ liệu.

---

### SR-05 - Deny Unauthorized Access

Nếu `role` không nằm trong danh sách được phép của một `key`, hàm `json_search()` không được trả về giá trị của `key` đó.

Kết quả phải là danh sách rỗng:

```python
[]
```

Ví dụ:

```python
json_search("apiKey", data, role="viewer")
```

phải trả về:

```python
[]
```

---

### SR-06 - Invalid Role

Nếu một role không hợp lệ hoặc không tồn tại trong `POLICY` cố gắng truy cập dữ liệu được bảo vệ, hàm không được trả về dữ liệu.

Ví dụ:

```python
json_search("apiKey", data, role="hacker")
```

phải bị từ chối và trả về:

```python
[]
```

---

### SR-07 - Policy Consistency

Quyền truy cập phải được lấy từ `POLICY` thay vì hard-code riêng trong từng trường hợp của hàm `json_search()`.

Điều này đảm bảo logic kiểm soát truy cập nhất quán với chính sách được định nghĩa trong `policy.py`.

---

## 3. Access Control Matrix

| Key                   | `admin` | `operator` | `viewer` |
| --------------------- | :-----: | :--------: | :------: |
| `apiKey`              |  ALLOW  |    DENY    |   DENY   |
| `managementIpAddress` |  ALLOW  |    ALLOW   |   DENY   |
| `issueSummary`        |  ALLOW  |    ALLOW   |   ALLOW  |

---

## 4. Security Test Basis

Các security requirement trên sẽ được sử dụng làm cơ sở để xây dựng security test.

Các trường hợp tối thiểu cần kiểm thử:

### Unauthorized access

1. `viewer` truy cập `apiKey` → phải DENY.
2. `operator` truy cập `apiKey` → phải DENY.
3. `viewer` truy cập `managementIpAddress` → phải DENY.
4. Role không hợp lệ truy cập dữ liệu được bảo vệ → phải DENY.

### Authorized access

1. `admin` truy cập `apiKey` → phải ALLOW.
2. `operator` truy cập `managementIpAddress` → phải ALLOW.
3. `viewer` truy cập `issueSummary` → phải ALLOW.

Các security test phải chứng minh rằng `json_search()` không chỉ tìm đúng `key` mà còn thực hiện kiểm soát quyền truy cập trước khi trả về dữ liệu.
