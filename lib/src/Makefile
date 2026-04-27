LIB_NAME = libdeepin-authenticate.so.1
LIB_DIR_NAME = libdeepin-authenticate
GDBUS_FILE = auth/com.deepin.daemon.Authenticate.c auth/com.deepin.daemon.Authenticate.Session.c
LIB_DEST_DIR=../../out/lib
PREFIX=/usr

ifeq (${DEB_HOST_MULTIARCH},)
DEB_HOST_MULTIARCH = $(shell dpkg-architecture -qDEB_HOST_MULTIARCH)
endif

PKG_CONFIG_LIB := $(shell pkg-config --libs glib-2.0 gio-unix-2.0 gtk+-2.0 json-c openssl json-glib-1.0)
PKG_CONFIG_INCLUDE := $(shell pkg-config --cflags glib-2.0 gio-unix-2.0 gtk+-2.0 json-c openssl json-glib-1.0)

all: build gen_pkgconfig

prepare:
	@mkdir -p ${LIB_DEST_DIR}

build: prepare ${GDBUS_FILE} ${LIB_NAME}

${LIB_NAME}: auth/*.c encrypt/*.c shm-comm/*.c
	gcc ${SECURITY_BUILD_OPTIONS} -shared -D_GNU_SOURCE -W -Wall -Wl,-soname,${LIB_NAME} -o $@ $^ -I../encrypt/ ${PKG_CONFIG_LIB} ${PKG_CONFIG_INCLUDE}
	mv ${LIB_NAME} ${LIB_DEST_DIR}

${GDBUS_FILE}:
	gdbus-codegen --generate-c-code=com.deepin.daemon.Authenticate auth/com.deepin.daemon.Authenticate.xml
	gdbus-codegen --annotate "com.deepin.daemon.Authenticate.Session.SetSymmetricKey()[key]" org.gtk.GDBus.C.ForceGVariant true --annotate "com.deepin.daemon.Authenticate.Session.SetToken()[token]" org.gtk.GDBus.C.ForceGVariant true --generate-c-code=com.deepin.daemon.Authenticate.Session auth/com.deepin.daemon.Authenticate.Session.xml

gen_pkgconfig:
	cd ../misc/pkgconfig;	\
	cp libdeepin-authenticate.pc.in libdeepin-authenticate.pc.in.copy;	\
	sed -i 's?@libdir@?${PREFIX}/lib/${DEB_HOST_MULTIARCH}?' libdeepin-authenticate.pc.in.copy;	\
	sed -i 's?@libappend@?${PKG_CONFIG_LIB}?' libdeepin-authenticate.pc.in.copy;	\
	sed -i 's?@includedir@?${PREFIX}/include/${LIB_DIR_NAME}?' libdeepin-authenticate.pc.in.copy;	\
	sed -i 's?@includeappend@?${PKG_CONFIG_INCLUDE}?' libdeepin-authenticate.pc.in.copy;	\
	mv libdeepin-authenticate.pc.in.copy libdeepin-authenticate.pc

install:
	mkdir -pv ${DESTDIR}${PREFIX}/lib/${DEB_HOST_MULTIARCH}
	cp -f ${LIB_DEST_DIR}/${LIB_NAME} ${DESTDIR}${PREFIX}/lib/${DEB_HOST_MULTIARCH}
	mkdir -pv ${DESTDIR}${PREFIX}/lib/${DEB_HOST_MULTIARCH}/pkgconfig
	cp -f ../misc/pkgconfig/*.pc ${DESTDIR}${PREFIX}/lib/${DEB_HOST_MULTIARCH}/pkgconfig
	mkdir -pv ${DESTDIR}${PREFIX}/include/${LIB_DIR_NAME}
	cp -f libdeepin-authenticate.h ${DESTDIR}${PREFIX}/include/${LIB_DIR_NAME}
	cp auth/auth.h auth/text.h ${DESTDIR}${PREFIX}/include/${LIB_DIR_NAME}
	cp encrypt/aes.h encrypt/rsa.h ${DESTDIR}${PREFIX}/include/${LIB_DIR_NAME}
	cp shm-comm/shmn_image.h shm-comm/shm_notifier.h ${DESTDIR}${PREFIX}/include/${LIB_DIR_NAME}

clean:
	rm -f ${LIB_NAME}
