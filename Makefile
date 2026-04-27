PREFIX = /usr
GOPATH_DIR = gopath
GOPKG_PREFIX = pkg.deepin.io/dde/authentication
GOBUILD = go build $(GO_BUILD_FLAGS)
#ifeq (${PAM_MODULE_DIR},)
#PAM_MODULE_DIR := /etc/pam.d
#endif
PKG_LIBS= openssl libsystemd json-c
BINARIES = deepin-authentication app-type-tool
LANGUAGES = $(basename $(notdir $(wildcard misc/po/*.po)))

export SECURITY_BUILD_OPTIONS = -fstack-protector-strong -D_FORTITY_SOURCE=1 -z noexecstack -pie -fPIC -z lazy
export GO111MODULE=off

all: build


prepare:
	@mkdir -p out/bin
	@if [ ! -d ${GOPATH_DIR}/src/${GOPKG_PREFIX} ]; then \
		mkdir -p ${GOPATH_DIR}/src/$(dir ${GOPKG_PREFIX}); \
		ln -sf ../../../.. ${GOPATH_DIR}/src/${GOPKG_PREFIX}; \
		fi

out/bin/%: prepare
	env GOPATH="${CURDIR}/${GOPATH_DIR}:${GOPATH}" ${GOBUILD} -o $@ ${GOBUILD_OPTIONS} ${GOPKG_PREFIX}/cmd/${@F}

out/pam_deepin_authentication.so: misc/pam-module/auth/*.c misc/pam-module/common/*.c
	gcc ${SECURITY_BUILD_OPTIONS} -shared -W -Wall -D_GNU_SOURCE -o $@ $^ $(foreach v, ${PKG_LIBS}, $(shell pkg-config --libs ${v})) -lpam -I./misc/pam-module/common
	chmod -x $@

build: prepare $(addprefix out/bin/, ${BINARIES}) ts_to_policy out/pam_deepin_authentication.so libdeepin-authenticate

print_gopath: prepare
	GOPATH="${CURDIR}/${GOPATH_DIR}:${GOPATH}"

install: translate install-pam-module
	install -d ${DESTDIR}${PREFIX}/share/locale
	- cp -rf out/locale/* ${DESTDIR}${PREFIX}/share/locale
	install -d ${DESTDIR}${PREFIX}/lib/deepin-authenticate/
	install -m755 out/bin/deepin-authentication ${DESTDIR}${PREFIX}/lib/deepin-authenticate/
	install -d ${DESTDIR}${PREFIX}/share/dbus-1/system.d
	install -m644 misc/conf/*.conf ${DESTDIR}${PREFIX}/share/dbus-1/system.d/
	install -d ${DESTDIR}/lib/systemd/system
	install -m644 misc/systemd/*.service ${DESTDIR}/lib/systemd/system/
	install -d ${DESTDIR}${PREFIX}/share/dbus-1/system-services
	install -m644 misc/system-services/* ${DESTDIR}${PREFIX}/share/dbus-1/system-services/
	install -d ${DESTDIR}/etc/pam.d
	install -m644 misc/pam.d/deepin_pam_unix ${DESTDIR}/etc/pam.d/
	install -d ${DESTDIR}/var/lib/deepin/authenticate
	install -m644 misc/authenticate-conf/* ${DESTDIR}/var/lib/deepin/authenticate/
	install -d ${DESTDIR}${PREFIX}/share/polkit-1/actions
	install -m644 misc/polkit-action/*.policy ${DESTDIR}${PREFIX}/share/polkit-1/actions/
	install -d ${DESTDIR}${PREFIX}/share/deepin-authentication/
	install -m644 misc/allowlist ${DESTDIR}${PREFIX}/share/deepin-authentication/
	install -m644 misc/app-type-list ${DESTDIR}${PREFIX}/share/deepin-authentication/
	install -m644 misc/mfa-force-disable ${DESTDIR}${PREFIX}/share/deepin-authentication/
	install -d ${DESTDIR}${PREFIX}/bin/
	install -m755 out/bin/app-type-tool ${DESTDIR}${PREFIX}/bin/
	$(MAKE) -C lib/src install

install-pam-module:
	install -d ${DESTDIR}/${PAM_MODULE_DIR}
	install -m644 out/pam_deepin_authentication.so ${DESTDIR}/${PAM_MODULE_DIR}

clean:
	rm -rf ${GOPATH_DIR}
	rm -rf out

pot:
	deepin-update-pot misc/po/locale_config.ini
	xgettext -j --from-code utf-8 misc/pam-module/auth/*.c -o misc/po/deepin-authentication.pot

POLICY_NAME = com.deepin.daemon.authenticate.Fingerprint com.deepin.daemon.authenticate.Face com.deepin.daemon.authenticate.Iris
ts:
	$(foreach policy,${POLICY_NAME},deepin-policy-ts-convert policy2ts misc/polkit-action/$(policy).policy.in misc/ts/$(policy).policy;)

ts_to_policy:
	$(foreach policy,${POLICY_NAME},deepin-policy-ts-convert ts2policy misc/polkit-action/$(policy).policy.in misc/ts/$(policy).policy misc/polkit-action/$(policy).policy;)

out/locale/%/LC_MESSAGES/deepin-authentication.mo: misc/po/%.po
	install -d $(@D)
	msgfmt -o $@ $<

translate: $(addsuffix /LC_MESSAGES/deepin-authentication.mo, $(addprefix out/locale/, ${LANGUAGES}))

test: prepare
	env GOPATH="${CURDIR}/${GOPATH_DIR}:${GOPATH}" go test -v ./...

test-coverage: prepare
	env GOPATH="${CURDIR}/${GOPATH_DIR}:${GOPATH}" go test -cover -v ./... | awk '$$1 ~ "(ok|\\?)" {print $$2","$$5}' | sed "s:${CURDIR}::g" | sed 's/files\]/0\.0%/g' > coverage.csv

libdeepin-authenticate:
	$(MAKE) -C lib/src
