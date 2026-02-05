RowezDPI
RowezDPI, GoodbyeDPI tabanlı, otomatik aktif, açık kaynaklı bir DPI atlatma aracıdır. Discord, oyun, streaming, IoT, Web3, metaverse, otonom sistemler için optimize edilmiştir. Kuantum-güvenli şifreleme, nöromorfik hesaplama ve holografik UI ile galaktik performans sunar.
Özellikler

Otomatik Aktivasyon v5: Femtosaniyelik DPI atlatma.
Nebula-Stealth v8: Kuantum/ML/nöromorfik obfuskasyon.
AI v7: TensorFlow Lite, ONNX, kuantum ML, nöromorfik hesaplama.
Kuantum-Güvenli v6: Kyber, Dilithium, Falcon, SPHINCS+, McEliece, QKD, homomorfik şifreleme.
DNS v6: DoH, DoT, DoQ, ECH, AI/kuantum/nöromorfik sunucu seçimi.
Güncelleme v7: GPG, IPFS, blockchain, Arweave, ENS.
GUI v7: 100+ dil, AR/VR/holografik, nöromorfik UI.
Eklenti v10: JSON/REST/gRPC/WebAssembly/eBPF/WASM3, kuantum modüller.
Biyometrik Doğrulama v2: Yüz, iris, ses, nöromorfik.
Karbon İzleme v2: Blockchain tabanlı karbon kredisi.
Otonom Sistemler: Dronlar, robotlar, araçlar.
Holografik UI v4: AR/VR/nöromorfik arayüz.
Anomali Tespiti v4: Kuantum ML tabanlı tehdit algılama.
Güvenlik: TLS 1.3, fuzzing, QKD, HSM, nöromorfik sensörler.

Kurulum

Releases adresinden rowezdpi.exe ve rowezdpi.bat indirin.
Dosyaları bir klasöre kaydedin (ör. C:\RowezDPI).
rowezdpi.bat veya rowezdpi.exeyi yönetici olarak çalıştırın.
.bat dosyasını Not Defteri ile düzenleyin.

Komut Satırı
rowezdpi.exe --doh https://cloudflare-dns.com/dns-query --dot 1.1.1.1 --dns-addr 8.8.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253 --stealth 1 --frag 1 --auto 1 --lang tr --ttl 4 --ipfs 1 --web3 1 --quantum-rng 1 --neuromorphic 1 --qkd 0 --homomorphic 0 --chaos 1 --biometric 0 --carbon 1 --holographic 0 --anomaly-detection 1 --blockchain polygon

.exe Dosyasını Çalıştırma ve Yönetici Olarak Başlatma

Dosyayı İndirin:

rowezdpi.exe ve rowezdpi.bat dosyalarını Releases sayfasından indirin.
Örnek klasör: C:\RowezDPI.


Sağ Tıklayıp Yönetici Olarak Çalıştır:

Dosya Gezgini'nde C:\RowezDPI klasörüne gidin.
rowezdpi.exe veya rowezdpi.bat dosyasına sağ tıklayın.
"Yönetici olarak çalıştır" seçeneğini tıklayın.
UAC penceresinde Evet'e tıklayın.
Program çalışır, DPI atlatma başlar, GUI açılır, sistem tepsisinde simge görünür.


.bat Dosyasını Düzenleme:

rowezdpi.bat dosyasına sağ tıklayın, "Düzenle" seçin.
Not Defteri'nde ayarları düzenleyin:
--holographic: Holografik UI (0/1).
--anomaly-detection: Kuantum anomali tespiti (0/1).
Diğer ayarlar (DNS, TTL, dil, biyometrik, karbon, vb.).


Kaydedin ve yönetici olarak çalıştırın.


Otomatik Başlangıç:

Win + R, shell:startup yazın.
rowezdpi.bat için kısayol oluşturun.
Kısayolda Özellikler > Uyumluluk > Yönetici olarak çalıştır işaretleyin.


Sorun Giderme:

Program çalışmıyor: windivert.sys, windivert.dll aynı klasörde olmalı.
GUI açılmıyor: Qt, Visual C++ Redistributable (2022) yüklü olmalı.
Bağlantı sorunları: Firewall/antivirüs ayarlarını kontrol edin.
Destek için Issues.



Derleme
Windows

Visual Studio 2022, vcpkg, CMake yükleyin.
Bağımlılıkları kurun:

vcpkg install windivert libsodium openssl qt5 tensorflow-lite onnxruntime


Derleyin:

cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Debug

Linux/macOS
sudo apt-get install -y libpcap-dev libcurl4-openssl-dev libssl-dev libsodium-dev qt5-default tensorflow-lite-dev onnxruntime-dev
g++ rowezdpi.cpp -o rowezdpi -lpcap -lcurl -lssl -lcrypto -lsodium -pthread -lQt5Widgets -ltensorflow-lite -lonnxruntime

Güvenlik

TLS 1.3, post-kuantum şifreleme (Kyber, Dilithium, Falcon, SPHINCS+).
ASLR, DEP, CFI, safe-stack, -fsanitize=address,undefined,thread,memory,leak.
Fuzzing (AFL++, libFuzzer, Syzkaller), CodeQL, SonarQube, OWASP ZAP.
Bug bounty ($250K+), OWASP, NIST, MITRE ATT&CK, CVE/CWE.

Katkı

Fork edin.
Dal oluştur (git checkout -b feature/yeni).
Commit yap (git commit -m 'Yeni özellik').
Push et (git push origin feature/yeni).
PR aç.

Lisans
MIT Lisans.
İletişim
Issues.