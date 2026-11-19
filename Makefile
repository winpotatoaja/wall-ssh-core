include $(TOPDIR)/rules.mk

PKG_NAME:=passwall-ssh-core
PKG_VERSION:=1.0.0
PKG_RELEASE:=19

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/passwall-ssh-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Non-blocking libssh2 SOCKS5 client core
  DEPENDS:=+libssh2 +libopenssl
endef

define Package/passwall-ssh-core/description
 A single-session SSH client core with a local SOCKS5 listener and multiplexed
 direct-tcpip channels.
endef

define Build/Prepare
	test -s ./ssh-core.c
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./ssh-core.c $(PKG_BUILD_DIR)/ssh-core.c
	test -s $(PKG_BUILD_DIR)/ssh-core.c
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -std=gnu11 \
		-Wall -Wextra \
		-o $(PKG_BUILD_DIR)/passwall-ssh-core $(PKG_BUILD_DIR)/ssh-core.c \
		$(TARGET_LDFLAGS) -Wl,--as-needed -lssh2 -lssl -lcrypto
	test -x $(PKG_BUILD_DIR)/passwall-ssh-core
endef

define Package/passwall-ssh-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/passwall-ssh-core $(1)/usr/bin/passwall-ssh-core
endef

$(eval $(call BuildPackage,passwall-ssh-core))
