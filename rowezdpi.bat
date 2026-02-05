@ECHO OFF
SETLOCAL

REM Çalıştırma dizinini scriptin olduğu yer yap
PUSHD "%~dp0"

REM Exe nerede? Genelde build/Debug altında olur
SET "EXE_PATH=build\Debug\rowezdpi.exe"

REM Eğer orada yoksa, script ile aynı yerdedir belki
IF NOT EXIST "%EXE_PATH%" (
    SET "EXE_PATH=rowezdpi.exe"
)

IF NOT EXIST "%EXE_PATH%" (
    ECHO HATA: rowezdpi.exe bulunamadi! Lutfen once projeyi derleyin.
    PAUSE
    GOTO :EOF
)

ECHO RowezDPI Baslatiliyor...
REM Yönetici hakları gerekebilir, kullanıcı uyarılmalı veya manifest ile halledilmeli
start "" "%EXE_PATH%" --doh https://cloudflare-dns.com/dns-query --dot 1.1.1.1 --stealth 1 --frag 1 --theme dark --auto 1 --lang tr

POPD
ENDLOCAL