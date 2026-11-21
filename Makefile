include $(TOPDIR)/rules.mk

PKG_NAME:=passwall-ssh-core
PKG_VERSION:=1.0.0
PKG_RELEASE:=26

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

# OpenWrt package architectures expose mipsel_24kc through ARCH_PACKAGES.
# Keep the ChaCha-first TLS policy scoped to that exact ABI/target only.
CORE_ARCH_CPPFLAGS:=
ifneq ($(filter mipsel_24kc,$(ARCH_PACKAGES) $(CONFIG_ARCH) $(ARCH)),)
  CORE_ARCH_CPPFLAGS+=-DSSH_CORE_MIPSEL_24KC=1
endif

define Package/passwall-ssh-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Multi-worker non-blocking libssh2 SOCKS5 client core
  DEPENDS:=+libssh2 +libopenssl
endef

define Package/passwall-ssh-core/description
 A pthread-based multi-worker SSH client core with independent libssh2 sessions
 and a SO_REUSEPORT SOCKS5 listener group.
endef

define Build/Prepare
	test -s ./ssh-core.c
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./ssh-core.c $(PKG_BUILD_DIR)/ssh-core.c
	test -s $(PKG_BUILD_DIR)/ssh-core.c
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(CORE_ARCH_CPPFLAGS) $(TARGET_CFLAGS) -std=gnu11 -pthread \
		-Wall -Wextra \
		-o $(PKG_BUILD_DIR)/passwall-ssh-core $(PKG_BUILD_DIR)/ssh-core.c \
		$(TARGET_LDFLAGS) -pthread -Wl,--as-needed -lssh2 -lssl -lcrypto
	test -x $(PKG_BUILD_DIR)/passwall-ssh-core
endef

define Package/passwall-ssh-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/passwall-ssh-core $(1)/usr/bin/passwall-ssh-core
endef

$(eval $(call BuildPackage,passwall-ssh-core))
