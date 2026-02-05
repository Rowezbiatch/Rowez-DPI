cmake_minimum_required(VERSION 3.20)

project(RowezDPI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt Autogen işlemleri
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Bağımlılıklar
find_package(WinDivert REQUIRED)
find_package(libsodium REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Qt5 COMPONENTS Widgets Network REQUIRED)
# vcpkg kullanıyorsanız bu paketlerin kurulu olduğundan emin olun
find_package(tensorflow-lite CONFIG REQUIRED)
find_package(onnxruntime CONFIG REQUIRED)

add_executable(rowezdpi rowezdpi.cpp)

target_link_libraries(rowezdpi PRIVATE
    WinDivert::WinDivert
    libsodium::libsodium
    OpenSSL::SSL OpenSSL::Crypto
    Qt5::Widgets Qt5::Network
    tensorflow-lite::tensorflow-lite
    onnxruntime::onnxruntime
)

# Derleme seçenekleri
if(MSVC)
    # Windows/MSVC için güvenli ayarlar
    target_compile_options(rowezdpi PRIVATE /W4 /EHsc /MTd)
    
    # Address Sanitizer sadece Debug modunda ve istenirse açılmalı
    target_compile_options(rowezdpi PRIVATE $<$<CONFIG:Debug>:/fsanitize=address>)
else()
    # GCC/Clang için
    target_compile_options(rowezdpi PRIVATE -Wall -Wextra -fsanitize=address)
endif()

# Güvenlik ve Optimizasyon Linker Ayarları
if(MSVC)
    target_link_options(rowezdpi PRIVATE
        /INCREMENTAL:NO 
        /OPT:REF 
        /OPT:ICF
        /DYNAMICBASE 
        /NXCOMPAT
        # /SAFESEH sadece x86 içindir, x64 buildlerde hata verebilir, o yüzden kaldırıldı veya koşullu eklenmeli.
    )
endif()