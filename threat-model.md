# Threat Model for `json_search()`

## 1. Actor / Role

Hệ thống có 3 role:

* `admin`: được phép truy cập các dữ liệu theo policy.
* `operator`: được phép truy cập `managementIpAddress` và `issueSummary`.
* `viewer`: chỉ được phép truy cập `issueSummary`.

Quyền truy cập được quy định trong `policy.py`.

## 2. Assets

Các dữ liệu cần bảo vệ trong JSON:

| Asset                 | Mô tả                     | Role được phép                |
| --------------------- | ------------------------- | ----------------------------- |
| `apiKey`              | Chuỗi xác thực SNMP       | `admin`                       |
| `managementIpAddress` | Địa chỉ quản trị thiết bị | `admin`, `operator`           |
| `issueSummary`        | Thông tin sự cố           | `admin`, `operator`, `viewer` |

## 3. Trust Boundary

Trust boundary nằm giữa **caller** và hàm `json_search()`.

Nếu `json_search()` chỉ tìm kiếm `key` mà không kiểm tra `role`, caller có thể lấy được dữ liệu mà role của mình không được phép truy cập.

Ví dụ:

```text
viewer → json_search("apiKey", data) → apiKey
```

Trong khi `apiKey` chỉ được phép cho `admin`.

## 4. Threats theo STRIDE

### T1 - Information Disclosure

`viewer` hoặc `operator` có thể yêu cầu `apiKey`. Nếu không kiểm tra role, giá trị `apiKey` có thể bị trả về.

* Asset: `apiKey`
* Unauthorized role: `viewer`, `operator`
* Impact: Lộ chuỗi xác thực SNMP.

### T2 - Information Disclosure

`viewer` có thể yêu cầu `managementIpAddress`. Nếu không kiểm tra role, địa chỉ quản trị thiết bị có thể bị tiết lộ.

* Asset: `managementIpAddress`
* Unauthorized role: `viewer`
* Impact: Lộ thông tin quản trị thiết bị.

### T3 - Elevation of Privilege

`viewer` có thể truy cập `apiKey`, mặc dù trường này chỉ dành cho `admin`.

* Actor: `viewer`
* Required role: `admin`
* Impact: Truy cập dữ liệu vượt quyền.

## 5. Kết luận

`json_search()` cần kiểm tra `role` với `POLICY` trước khi trả về dữ liệu.

Nguyên tắc:

> Nếu role không nằm trong danh sách được phép của key thì không trả về dữ liệu và kết quả phải là `[]`.

Threat model này là cơ sở để xây dựng các security test ở bước tiếp theo.
