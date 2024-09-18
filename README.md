This is a modified version of WolfSSl client-tls.c

to use copy your needed certificate to `sd/_nds/certs/example.crt`
 and fill in `char request_text` with your http request

## Building
Build the library 
```
git clone https://github.com/buchstabenwurst/wolfssl-nds.git
cd ./wolfssl-nds
./configure \
    --host=arm-none-eabi \
    CC=$DEVKITARM/bin/arm-none-eabi-g++ \
    AR=$DEVKITARM/bin/arm-none-eabi-ar \
    STRIP=$DEVKITARM/bin/arm-none-eabi-strip \
    RANLIB=$DEVKITARM/bin/arm-none-eabi-ranlib \
    LIBS="-lfat -lnds9" \
    LDFLAGS="-L/opt/devkitpro/libnds/lib" \
    --prefix=$DEVKITPRO/portlibs/nds \
    CFLAGS="-march=armv5te -mtune=arm946e-s \
        --specs=ds_arm9.specs -DARM9 -DNDS \
        -DWOLFSSL_USER_IO \
        -I$DEVKITPRO/libnds/include" \
    --enable-fastmath --disable-benchmark \
    --disable-shared --disable-examples --disable-ecc
make
sudo make install
```
then return to this repository folder and simply run
```
make
```