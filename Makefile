include $(TOPDIR)/rules.mk

PKG_NAME:=passwall-ssh-core
PKG_VERSION:=1.0.0
PKG_RELEASE:=51

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

# OpenWrt package architectures expose mipsel_24kc through ARCH_PACKAGES.
# Keep the MIPS-specific TLS cipher preference and atomic helper scoped to
# the MT7621 mipsel_24kc ABI.
CORE_ARCH_CPPFLAGS:=
CORE_ARCH_LDLIBS:=
ifneq ($(filter mipsel_24kc,$(ARCH_PACKAGES) $(CONFIG_ARCH) $(ARCH)),)
  CORE_ARCH_CPPFLAGS+=-DSSH_CORE_MIPSEL_24KC=1
  CORE_ARCH_LDLIBS+=-latomic
endif

define Package/passwall-ssh-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Single-session non-blocking libssh2 SOCKS5 relay core
  DEPENDS:=+libssh2 +libopenssl
endef

define Package/passwall-ssh-core/description
 A single-session libssh2 SSH client core that multiplexes local SOCKS5 clients
 over direct-tcpip channels. Auxiliary multithreaded I/O is being developed separately.
endef

define Build/Prepare
	test -s ./ssh-core.c
	test -s ./tls_engine.c
	test -s ./tls_engine.h
	test -s ./libssh2_diag.h
	test -s ./client_event_token.h
	test -s ./client_lifetime.h
	test -s ./client_lifetime.c
	test -s ./io_worker_completion_tracker.h
	test -s ./io_worker_completion_tracker.c
	test -s ./spsc_rb.h
	test -s ./io_worker_pool.c
	test -s ./io_worker_pool.h
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./ssh-core.c $(PKG_BUILD_DIR)/ssh-core.c
	$(CP) ./tls_engine.c $(PKG_BUILD_DIR)/tls_engine.c
	$(CP) ./tls_engine.h $(PKG_BUILD_DIR)/tls_engine.h
	$(CP) ./libssh2_diag.h $(PKG_BUILD_DIR)/libssh2_diag.h
	$(CP) ./client_event_token.h $(PKG_BUILD_DIR)/client_event_token.h
	$(CP) ./client_lifetime.h $(PKG_BUILD_DIR)/client_lifetime.h
	$(CP) ./client_lifetime.c $(PKG_BUILD_DIR)/client_lifetime.c
	$(CP) ./io_worker_completion_tracker.h $(PKG_BUILD_DIR)/io_worker_completion_tracker.h
	$(CP) ./io_worker_completion_tracker.c $(PKG_BUILD_DIR)/io_worker_completion_tracker.c
	$(CP) ./spsc_rb.h $(PKG_BUILD_DIR)/spsc_rb.h
	$(CP) ./io_worker_pool.c $(PKG_BUILD_DIR)/io_worker_pool.c
	$(CP) ./io_worker_pool.h $(PKG_BUILD_DIR)/io_worker_pool.h
	test -s $(PKG_BUILD_DIR)/ssh-core.c
	test -s $(PKG_BUILD_DIR)/tls_engine.c
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(CORE_ARCH_CPPFLAGS) $(TARGET_CFLAGS) -std=gnu11 -pthread \
		-Wall -Wextra \
		-o $(PKG_BUILD_DIR)/passwall-ssh-core $(PKG_BUILD_DIR)/ssh-core.c $(PKG_BUILD_DIR)/tls_engine.c $(PKG_BUILD_DIR)/io_worker_pool.c $(PKG_BUILD_DIR)/client_lifetime.c $(PKG_BUILD_DIR)/io_worker_completion_tracker.c \
		$(TARGET_LDFLAGS) -pthread -Wl,--as-needed -lssh2 -lssl -lcrypto $(CORE_ARCH_LDLIBS)
	test -x $(PKG_BUILD_DIR)/passwall-ssh-core
endef

define Package/passwall-ssh-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/passwall-ssh-core $(1)/usr/bin/passwall-ssh-core
endef

$(eval $(call BuildPackage,passwall-ssh-core))
