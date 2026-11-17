#
# OpenWrt package for the Localport agent and the no-PAM localport-session.
# Built per package architecture with the OpenWrt SDK by
# packaging/openwrt/sdk.sh, which fills in @VERSION@ and @HASH@ from the
# source tarball it makes of the checked-out tree. Follows the layout of the
# golang feed's Go packages in openwrt/packages.
#
# No init scripts: `localport up` writes the procd scripts for both
# services. The package creates the system user and group localport (USERID).
#

include $(TOPDIR)/rules.mk

PKG_NAME:=localport
PKG_VERSION:=@VERSION@
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/localport/agent/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=@HASH@

PKG_MAINTAINER:=Localport <support@localport.io>
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DIR:=$(BUILD_DIR)/agent-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=golang1.27/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/localport/agent
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/localport $(GO_PKG)/cmd/localport-session
GO_PKG_LDFLAGS_X:=main.version=v$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/localport
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Localport agent: secure tunnels and remote access
  URL:=https://localport.io
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
  # opkg creates the account with OpenWrt's default home and shell; the
  # Linux packages use /nonexistent and nologin (packaging/nfpm/sysusers.conf).
  USERID:=localport:localport
endef

define Package/localport/description
  Publishes services over secure HTTP, TCP and TLS tunnels, and gives
  identity-based remote access to devices in a Localport fleet. Ships the
  agent and localport-session built without PAM.
endef

define Package/localport/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/localport $(1)/usr/bin/
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/localport-session $(1)/usr/bin/
endef

$(eval $(call BuildPackage,localport))
