#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 PATH_TO_KERNEL"
    exit 1
fi
if [ $(dirname $0) != "." ]; then
    echo "Script must be run directly in the ynl-c directory"
    exit 1
fi

KSRC=$1

make -C ${KSRC}/tools/net/ynl -j $(nproc) || exit 1

cp -v ${KSRC}/tools/net/ynl/Makefile.deps	./
sed -i 's@^UAPI_PATH:=.*@UAPI_PATH:=../include/@' Makefile.deps

mkdir -p include/linux/
for hdr in $(cat Makefile.deps | sed -n 's/.*,\([^,]*\.h\)).*/\1/p'); do
    cp -v  ${KSRC}/include/uapi/linux/$hdr	./include/linux/$hdr
done

mkdir -p lib
cp -v ${KSRC}/tools/net/ynl/lib/*.c		./

mkdir -p generated
cp -v ${KSRC}/tools/net/ynl/generated/*.{c,h}	./generated/

mkdir -p include/ynl-c
cp -v ${KSRC}/tools/net/ynl/lib/*.h		./include/ynl-c/
for hdr in $(ls generated/ | grep -user.h); do
    mv -v generated/$hdr			./include/ynl-c/${hdr/-user/}
    (
	cd generated
	ln -svf ../include/ynl-c/${hdr/-user/}	./$hdr
    )
done
