APP_NAME = ESGuard
BUNDLE_ID = dev.codex-es-guard.menubar
BUILD_DIR = .build/arm64-apple-macosx/release
EXECUTABLE = $(BUILD_DIR)/ESGuardMenuBar
APP_BUNDLE = $(APP_NAME).app
CONTENTS = $(APP_BUNDLE)/Contents
MACOS = $(CONTENTS)/MacOS
RESOURCES = $(CONTENTS)/Resources
USER_APPS = ~/Applications
# 使用 macOS 系统自带的"保险箱/护盾"高质量图标
SYSTEM_ICON = /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/FileVaultIcon.icns

.PHONY: all build bundle run install clean

all: bundle

build:
	swift build -c release

bundle: build
	mkdir -p $(MACOS) $(RESOURCES)
	cp $(EXECUTABLE) $(MACOS)/$(APP_NAME)
	# 拷贝系统图标并命名为 AppIcon.icns
	cp $(SYSTEM_ICON) $(RESOURCES)/AppIcon.icns
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > $(CONTENTS)/Info.plist
	@echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> $(CONTENTS)/Info.plist
	@echo '<plist version="1.0">' >> $(CONTENTS)/Info.plist
	@echo '<dict>' >> $(CONTENTS)/Info.plist
	@echo '	<key>CFBundleExecutable</key>' >> $(CONTENTS)/Info.plist
	@echo '	<string>$(APP_NAME)</string>' >> $(CONTENTS)/Info.plist
	@echo '	<key>CFBundleIdentifier</key>' >> $(CONTENTS)/Info.plist
	@echo '	<string>$(BUNDLE_ID)</string>' >> $(CONTENTS)/Info.plist
	@echo '	<key>CFBundleName</key>' >> $(CONTENTS)/Info.plist
	@echo '	<string>$(APP_NAME)</string>' >> $(CONTENTS)/Info.plist
	@echo '	<key>CFBundlePackageType</key>' >> $(CONTENTS)/Info.plist
	@echo '	<string>APPL</string>' >> $(CONTENTS)/Info.plist
	@echo '	<key>CFBundleShortVersionString</key>' >> $(CONTENTS)/Info.plist
	@echo '	<string>1.0</string>' >> $(CONTENTS)/Info.plist
	@echo '	<key>CFBundleVersion</key>' >> $(CONTENTS)/Info.plist
	@echo '	<string>1</string>' >> $(CONTENTS)/Info.plist
	@echo '	<key>LSUIElement</key>' >> $(CONTENTS)/Info.plist
	@echo '	<true/>' >> $(CONTENTS)/Info.plist
	@echo '	<key>CFBundleIconFile</key>' >> $(CONTENTS)/Info.plist
	@echo '	<string>AppIcon</string>' >> $(CONTENTS)/Info.plist
	@echo '</dict>' >> $(CONTENTS)/Info.plist
	@echo '</plist>' >> $(CONTENTS)/Info.plist

install: bundle
	@echo "Installing $(APP_NAME) to $(USER_APPS)..."
	mkdir -p $(USER_APPS)
	# 杀掉可能正在运行的旧版本
	-killall $(APP_NAME) 2>/dev/null || true
	# 移除旧版本
	rm -rf $(USER_APPS)/$(APP_BUNDLE)
	# 复制新版本
	cp -R $(APP_BUNDLE) $(USER_APPS)/
	# macOS 隔离属性修复
	xattr -rd com.apple.quarantine $(USER_APPS)/$(APP_BUNDLE) 2>/dev/null || true
	# 强制 Finder 更新图标缓存
	touch $(USER_APPS)/$(APP_BUNDLE)
	# 重新启动它
	open $(USER_APPS)/$(APP_BUNDLE)
	@echo "Successfully installed! $(APP_NAME) is now running from $(USER_APPS)."

run: bundle
	# 先停止已有实例
	-killall $(APP_NAME) 2>/dev/null || true
	open $(APP_BUNDLE)

clean:
	rm -rf .build $(APP_BUNDLE)
