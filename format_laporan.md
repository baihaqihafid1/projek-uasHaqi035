# UAS Pengembangan Web – Debug REST API CI4

## Tugas:
- Perbaiki minimal 5 bug dari aplikasi
- Catat bug dan solusinya dalam tabel laporan

---

### ✅ Laporan Bug

| No | File                          | Baris | Bug                                                       | Solusi                                                                 |
|----|-------------------------------|-------|------------------------------------------------------------|------------------------------------------------------------------------|
| 1  | app/Controllers/AuthController.php | 17    | Class `JWTLibrary` error                                   | Buat file `app/Libraries/JWTLibrary.php` dan pastikan namespace sesuai |
| 2  | app/Controllers/AuthController.php | 33    | Tidak ada validasi input saat register                     | Tambahkan validasi menggunakan `$this->validate()`                     |
| 3  | app/Controllers/AuthController.php | 40    | Password tidak di-hash                                     | Ubah ke `password_hash($pass, PASSWORD_DEFAULT)`                       |
| 4  | app/Controllers/AuthController.php | 45    | Password dikirim kembali dalam response                    | Gunakan `unset($userData['password'])` sebelum `respond()`             |
| 5  | app/Controllers/AuthController.php | 62    | Perbandingan password masih plain text                     | Ganti ke `password_verify($password, $user['password'])`               |
| 6  | app/Models/UserModel.php      | -     | Hashing menggunakan MD5 yang lemah                         | Ganti ke `password_hash` di Controller, hapus fungsi beforeInsert      |
| 7  | app/Models/UserModel.php      | -     | Tidak ada `validationRules` dan `useTimestamps`            | Tambahkan rules dan aktifkan `useTimestamps = true`                    |
| 8  | app/Config/Routes.php         | -     | Filter `auth` salah untuk tasks                            | Ubah ke `jwt` agar sesuai filter yang ada                             |
| 9  | .env                          | -     | JWT_SECRET tidak disetel                                   | Tambahkan `JWT_SECRET=your_secret_key`                                |
| 10 | Postman Header                | -     | Body tidak dikenali karena tidak pakai `Content-Type` JSON | Tambahkan Header `Content-Type: application/json` di Postman          |

---

## 🔁 Uji API dengan Postman:

### ✅ Register
- **Method**: POST  
- **Endpoint**: `http://localhost:8080/api/auth/register`  
- **Body (JSON)**:
```json
{
  "name": "Haqi",
  "email": "baihaqi123@example.com",
  "password": "haqi12345"
}
